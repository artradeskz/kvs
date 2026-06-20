#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Кодировщик инструкций переменного размера для КВС
Автономный модуль — не импортирует из kvs_pass2_encoder_fixsize.
Содержит parse_operand, parse_memory_operand, инструкции с адресацией, диспетчер.
Дублируемые с fixsize функции помечены комментарием # ДУБЛИКАТ.

ФОРМАТ ВХОДНЫХ ДАННЫХ:
- operands: список строк, по одной на операнд
- Для косвенной адресации: 'MEM:reg_indirect:имя_регистра' (например 'MEM:reg_indirect:рбикс')
- Для абсолютной адресации: '[число]' или '[метка]' (старый формат)
- Для регистров: имя регистра (например 'раикс')
- Для непосредственных значений: число или метка

СТРУКТУРА REGISTERS (из kvs_data.py):
- Ключ: имя регистра (строка, например "раикс", "рбикс")
- Значение: индекс регистра (целое число 0-15)
- Пример: REGISTERS["раикс"] = 0, REGISTERS["рбикс"] = 3

СТРУКТУРА get_reg_info(reg_name):
- Возвращает словарь: {"size": 64, "index": 0} для 64-битных
- "index" — индекс регистра (0-15), используется в ModR/M и REX
- "size" — размер в битах (8, 16, 32, 64)
"""

import struct
import sys
from kvs_data import INSTRUCTIONS, REGISTERS, get_reg_info


# ========== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ==========

def parse_operand(operand, labels, label_sections, symbols, vaddr_text, vaddr_data, vaddr_bnd=None):
    """
    Вычисляет значение операнда.
    Поддерживает:
    - десятичные числа (123)
    - шестнадцатеричные (0x7B)
    - метки (имя_метки) — из .text, .data или .бнд
    - константы (из .константа)
    """
    if operand.isdigit():
        return int(operand)
    if operand.startswith('0x') or operand.startswith('0X'):
        try:
            return int(operand, 16)
        except ValueError:
            pass
    if operand in labels:
        section = label_sections.get(operand, '.text')
        if section == '.text':
            return labels[operand] + vaddr_text
        elif section == '.data':
            return labels[operand] + vaddr_data
        elif section == '.бнд':
            return labels[operand] + vaddr_bnd
        else:
            return labels[operand] + vaddr_text
    if operand in symbols:
        return symbols[operand]
    raise ValueError("Неизвестный операнд: " + operand)


def parse_memory_operand(operand_str, labels, label_sections, vaddr_text, vaddr_data, vaddr_bnd=None):
    """
    Разбирает операнд памяти.
    Возвращает словарь с информацией или None.
    
    Поддерживаемые форматы:
    - [число] — абсолютный адрес
    - [метка] — адрес метки (из .data, .text или .бнд)
    - MEM:reg_indirect:регистр — косвенная адресация (новый формат)
    - MEM:absolute:число — абсолютный адрес (новый формат, для будущего использования)
    - MEM:absolute:метка — абсолютный адрес по метке (новый формат, для будущего использования)
    
    Возвращаемый словарь:
    - Для 'absolute': {'type': 'absolute', 'address': число}
    - Для 'register_indirect': {'type': 'register_indirect', 'base_reg': имя_регистра}
    """
    # --- Новый формат: MEM:тип:данные ---
    if operand_str.startswith('MEM:'):
        parts = operand_str.split(':')
        if len(parts) >= 3:
            addr_type = parts[1]
            
            if addr_type == 'reg_indirect':
                # MEM:reg_indirect:имя_регистра
                base_reg = parts[2]
                if base_reg in REGISTERS:
                    return {'type': 'register_indirect', 'base_reg': base_reg}
            
            elif addr_type == 'absolute':
                # MEM:absolute:число или MEM:absolute:метка
                value = parts[2]
                if value.isdigit():
                    return {'type': 'absolute', 'address': int(value)}
                elif value.startswith('0x') or value.startswith('0X'):
                    try:
                        return {'type': 'absolute', 'address': int(value, 16)}
                    except ValueError:
                        pass
                elif value in labels:
                    section = label_sections.get(value, '.data')
                    if section == '.text':
                        base = vaddr_text
                    elif section == '.data':
                        base = vaddr_data
                    elif section == '.бнд':
                        base = vaddr_bnd
                    else:
                        base = vaddr_text
                    addr = labels[value] + base
                    return {'type': 'absolute', 'address': addr}
        
        return None
    
    # --- Старый формат: [число] или [метка] ---
    if not operand_str.startswith('[') or not operand_str.endswith(']'):
        return None
    
    content = operand_str[1:-1].strip()
    
    if content.isdigit():
        return {'type': 'absolute', 'address': int(content)}
    elif content.startswith('0x') or content.startswith('0X'):
        try:
            return {'type': 'absolute', 'address': int(content, 16)}
        except ValueError:
            pass
    
    if content in labels:
        section = label_sections.get(content, '.data')
        if section == '.text':
            base = vaddr_text
        elif section == '.data':
            base = vaddr_data
        elif section == '.бнд':
            base = vaddr_bnd
        else:
            base = vaddr_text
        addr = labels[content] + base
        return {'type': 'absolute', 'address': addr}
    
    return None


# ========== MOV С ПАМЯТЬЮ ==========

def encode_mov_reg_mem_absolute(reg_info, mem_info, current_pos, vaddr_text):
    """Кодирует MOV reg, [addr] через RIP-relative адресацию"""
    code = bytearray()
    reg = reg_info['index']
    target_addr = mem_info['address']
    rip_at_end = vaddr_text + current_pos + 7
    offset = target_addr - rip_at_end
    
    rex = 0x48 if reg_info['size'] == 64 else 0x40
    if reg >= 8:
        rex |= 0x01
    code.append(rex)
    code.append(0x8B)
    modrm = 0x05 | ((reg & 7) << 3)
    code.append(modrm)
    code.extend(struct.pack('<i', offset))
    return code


def encode_mov_mem_reg_absolute(reg_info, mem_info, current_pos, vaddr_text):
    """Кодирует MOV [addr], reg через RIP-relative адресацию"""
    code = bytearray()
    reg = reg_info['index']
    target_addr = mem_info['address']
    rip_at_end = vaddr_text + current_pos + 7
    offset = target_addr - rip_at_end
    
    rex = 0x48 if reg_info['size'] == 64 else 0x40
    if reg >= 8:
        rex |= 0x01
    code.append(rex)
    code.append(0x89)
    modrm = 0x05 | ((reg & 7) << 3)
    code.append(modrm)
    code.extend(struct.pack('<i', offset))
    return code


def encode_mov_reg_mem_indirect(reg_info: dict, base_reg: str) -> bytearray:
    """
    Кодирует MOV reg, [base_reg] — косвенная адресация через регистр.
    """
    code = bytearray()
    
    # === 1. Получаем индексы регистров ===
    reg_index = reg_info['index']
    reg_size = reg_info['size']
    
    if base_reg not in REGISTERS:
        raise ValueError(f"Неизвестный базовый регистр: {base_reg}")
    base_index = REGISTERS[base_reg]
    
    # === 2. Выбираем opcode и префиксы ===
    #
    # В x86-64 для MOV существуют разные opcodes:
    #   - 8A /r  — MOV r8, r/m8  (только 8-бит!)
    #   - 8B /r  — MOV r16/r32/r64, r/m16/r/m32/r/m64
    # 
    # Для 16-бит нужен префикс 0x66
    # Для 64-бит нужен REX.W (бит 3 в REX)
    #
    if reg_size == 8:
        opcode = 0x8A          # MOV r8, r/m8
        rex_base = 0x40        # Без REX.W
        need_prefix_66 = False
    elif reg_size == 16:
        opcode = 0x8B          # MOV r16, r/m16
        rex_base = 0x40        # Без REX.W
        need_prefix_66 = True   # ← ВАЖНО: префикс 0x66 для 16-бит!
    elif reg_size == 32:
        opcode = 0x8B          # MOV r32, r/m32
        rex_base = 0x40        # Без REX.W
        need_prefix_66 = False
    elif reg_size == 64:
        opcode = 0x8B          # MOV r64, r/m64
        rex_base = 0x48        # С REX.W (бит 3 = 1)
        need_prefix_66 = False
    else:
        raise ValueError(f"Неподдерживаемый размер регистра: {reg_size} бит")
    
    # === 3. Формируем REX-префикс ===
    rex = rex_base
    
    # REX.R: для регистра-источника (reg) — нужен если индекс >= 8
    if reg_index >= 8:
        rex |= 0x04  # REX.R = 1
    
    # REX.B: для базового регистра (base) — нужен если индекс >= 8
    if base_index >= 8:
        rex |= 0x01  # REX.B = 1
    
    # === 4. Формируем ModR/M байт ===
    if (base_index & 7) == 5:
        # [rbp] или [r13] требуют disp8=0
        modrm = 0x40 | ((reg_index & 7) << 3) | 5
        modrm_byte = modrm
        disp8 = 0x00
    else:
        modrm = ((reg_index & 7) << 3) | (base_index & 7)
        modrm_byte = modrm
        disp8 = None
    
    # === 5. Собираем инструкцию ===
    
    # 5a. Префикс 0x66 для 16-битных операндов (ДО REX!)
    if need_prefix_66:
        code.append(0x66)
    
    # 5b. REX-префикс (если не равен 0x40)
    if rex != 0x40:
        code.append(rex)
    
    # 5c. Opcode
    code.append(opcode)
    
    # 5d. ModR/M байт
    code.append(modrm_byte)
    
    # 5e. Disp8 (если есть)
    if disp8 is not None:
        code.append(disp8)
    
    return code
    
def encode_mov_mem_reg_indirect(base_reg, reg_info):
    """
    Кодирует MOV [base_reg], reg — косвенная адресация.
    Пример: mov [rsi], rax → 48 89 06
    
    Аргументы:
    - base_reg: строка с именем регистра, например 'рсикс'
    - reg_info: словарь от get_reg_info() с ключами 'index' (int) и 'size' (int)
    
    REGISTERS[base_reg] возвращает число-индекс (int), НЕ словарь.
    """
    code = bytearray()
    reg = reg_info['index']
    base = REGISTERS[base_reg]  # REGISTERS возвращает int (индекс регистра)
    
    rex = 0x48 if reg_info['size'] == 64 else 0x40
    if reg >= 8:
        rex |= 0x04  # REX.R
    if base >= 8:
        rex |= 0x01  # REX.B
    code.append(rex)
    code.append(0x89)  # MOV r/m64, r64
    
    # Особый случай: [rbp] или [r13] требует disp8=0 при mod=00
    if (base & 7) == 5:
        modrm = 0x40 | ((reg & 7) << 3) | 5
        code.append(modrm)
        code.append(0x00)
    else:
        modrm = ((reg & 7) << 3) | (base & 7)
        code.append(modrm)
    
    return code


def encode_mov_reg_mem(operands, labels, label_sections, symbols, vaddr_text, vaddr_data, current_pos, vaddr_bnd=None):
    """MOV reg, mem — загрузить"""
    reg_info = get_reg_info(operands[0])
    mem_operand = operands[1]
    mem_info = parse_memory_operand(mem_operand, labels, label_sections, vaddr_text, vaddr_data, vaddr_bnd)
    
    if mem_info:
        if mem_info['type'] == 'absolute':
            return encode_mov_reg_mem_absolute(reg_info, mem_info, current_pos, vaddr_text)
        elif mem_info['type'] == 'register_indirect':
            return encode_mov_reg_mem_indirect(reg_info, mem_info['base_reg'])
    
    print(f"Предупреждение: сложная адресация '{mem_operand}' пока не поддерживается", file=sys.stderr)
    return b'\x90' * 3


def encode_mov_mem_reg(operands, labels, label_sections, symbols, vaddr_text, vaddr_data, current_pos, vaddr_bnd=None):
    """MOV mem, reg — сохранить"""
    mem_operand = operands[0]
    reg_info = get_reg_info(operands[1])
    mem_info = parse_memory_operand(mem_operand, labels, label_sections, vaddr_text, vaddr_data, vaddr_bnd)
    
    if mem_info:
        if mem_info['type'] == 'absolute':
            return encode_mov_mem_reg_absolute(reg_info, mem_info, current_pos, vaddr_text)
        elif mem_info['type'] == 'register_indirect':
            return encode_mov_mem_reg_indirect(mem_info['base_reg'], reg_info)
    
    print(f"Предупреждение: сложная адресация '{mem_operand}' пока не поддерживается", file=sys.stderr)
    return b'\x90' * 3


def encode_lea_mem(operands, labels, label_sections, symbols, vaddr_text, vaddr_data, current_pos, vaddr_bnd=None):
    """LEA reg, mem — загрузить_адрес"""
    reg_info = get_reg_info(operands[0])
    mem_operand = operands[1]
    mem_info = parse_memory_operand(mem_operand, labels, label_sections, vaddr_text, vaddr_data, vaddr_bnd)
    if mem_info and mem_info['type'] == 'absolute':
        target_addr = mem_info['address']
        rip_at_end = vaddr_text + current_pos + 7
        offset = target_addr - rip_at_end
        code = bytearray()
        reg = reg_info['index']
        rex = 0x48 if reg_info['size'] == 64 else 0x40
        if reg >= 8:
            rex |= 0x01
        if rex != 0x40:
            code.append(rex)
        code.append(0x8D)
        modrm = 0x05 | ((reg & 7) << 3)
        code.append(modrm)
        code.extend(struct.pack('<i', offset))
        return code
    print(f"Предупреждение: LEA с адресацией '{mem_operand}' пока не поддерживается", file=sys.stderr)
    return b'\x90' * 3


# ========== MOV reg, imm ==========

def encode_mov_reg_imm(operands, labels, label_sections, symbols, vaddr_text, vaddr_data, vaddr_bnd=None):
    """MOV reg, imm — переместить_имм"""
    code = bytearray()
    reg_info = get_reg_info(operands[0])
    reg = reg_info["index"]
    size = reg_info["size"]
    imm = parse_operand(operands[1], labels, label_sections, symbols, vaddr_text, vaddr_data, vaddr_bnd)

    if size == 64:
        if 0 <= reg <= 7:
            code.extend(b'\x48')
            code.append(0xB8 + reg)
        elif 8 <= reg <= 15:
            code.extend(b'\x49')
            code.append(0xB8 + (reg - 8))
        code.extend(struct.pack('<Q', imm & 0xFFFFFFFFFFFFFFFF))
    elif size == 32:
        rex = 0x40
        if reg >= 8:
            rex |= 0x01
        if rex != 0x40:
            code.append(rex)
        code.append(0xC7)
        modrm = 0xC0 | (reg & 7)
        code.append(modrm)
        code.extend(struct.pack('<I', imm & 0xFFFFFFFF))
    elif size == 16:
        code.append(0x66)
        rex = 0x40
        if reg >= 8:
            rex |= 0x01
        if rex != 0x40:
            code.append(rex)
        code.append(0xC7)
        modrm = 0xC0 | (reg & 7)
        code.append(modrm)
        code.append(imm & 0xFF)
        code.append((imm >> 8) & 0xFF)
    elif size == 8:
        if reg_info.get("high8"):
            code.append(0xB0 + reg + 4)
        else:
            if reg < 4:
                code.append(0xB0 + reg)
            else:
                rex = 0x40
                if reg >= 8:
                    rex |= 0x01
                code.append(rex)
                code.append(0xB0 + (reg & 7))
        code.append(imm & 0xFF)
    return code


# ========== MOVZX/MOVSX ==========

def encode_movzx(operands, labels, label_sections, symbols, vaddr_text, vaddr_data, vaddr_bnd=None):
    """MOVZX reg, mem8 — переместить_с_нулями"""
    code = bytearray()
    instr = INSTRUCTIONS["переместить_с_нулями"]
    reg_info = get_reg_info(operands[0])
    reg = reg_info["index"]
    addr = parse_operand(operands[1], labels, label_sections, symbols, vaddr_text, vaddr_data, vaddr_bnd)
    rex = 0x48 if reg_info["size"] == 64 else 0x40
    if reg >= 8:
        rex |= 0x01
    code.append(rex)
    code.extend(instr["opcode"])
    modrm = 0x05 | ((reg & 7) << 3)
    code.append(modrm)
    code.extend(struct.pack('<i', addr))
    return code


def encode_movsx(operands, labels, label_sections, symbols, vaddr_text, vaddr_data, vaddr_bnd=None):
    """MOVSX reg, mem8 — переместить_со_знаком"""
    code = bytearray()
    instr = INSTRUCTIONS["переместить_со_знаком"]
    reg_info = get_reg_info(operands[0])
    reg = reg_info["index"]
    addr = parse_operand(operands[1], labels, label_sections, symbols, vaddr_text, vaddr_data, vaddr_bnd)
    rex = 0x48 if reg_info["size"] == 64 else 0x40
    if reg >= 8:
        rex |= 0x01
    code.append(rex)
    code.extend(instr["opcode"])
    modrm = 0x05 | ((reg & 7) << 3)
    code.append(modrm)
    code.extend(struct.pack('<i', addr))
    return code


# ========== CMP reg, imm ==========

def encode_cmp_reg_imm(operands, labels, label_sections, symbols, vaddr_text, vaddr_data, vaddr_bnd=None):
    """CMP reg, imm — сравнить_с"""
    code = bytearray()
    reg_info = get_reg_info(operands[0])
    reg = reg_info["index"]
    size = reg_info["size"]
    imm = parse_operand(operands[1], labels, label_sections, symbols, vaddr_text, vaddr_data, vaddr_bnd)

    if size == 64:
        rex = 0x48
        if reg >= 8:
            rex |= 0x01
        code.append(rex)
        code.append(0x81)
        modrm = 0xF8 | (reg & 7)
        code.append(modrm)
        code.extend(struct.pack('<i', imm))
    elif size == 32:
        if -128 <= imm <= 127:
            rex = 0x40
            if reg >= 8:
                rex |= 0x01
            if rex != 0x40:
                code.append(rex)
            code.append(0x83)
            modrm = 0xF8 | (reg & 7)
            code.append(modrm)
            code.append(imm & 0xFF)
        else:
            rex = 0x40
            if reg >= 8:
                rex |= 0x01
            if rex != 0x40:
                code.append(rex)
            code.append(0x81)
            modrm = 0xF8 | (reg & 7)
            code.append(modrm)
            code.extend(struct.pack('<I', imm & 0xFFFFFFFF))
    elif size == 16:
        code.append(0x66)
        rex = 0x40
        if reg >= 8:
            rex |= 0x01
        if rex != 0x40:
            code.append(rex)
        code.append(0x81)
        modrm = 0xF8 | (reg & 7)
        code.append(modrm)
        code.extend(struct.pack('<H', imm & 0xFFFF))
    elif size == 8:
        if reg_info.get("high8"):
            code.append(0x80)
            modrm = 0xF8 | reg
            code.append(modrm)
        else:
            if reg < 4:
                code.append(0x80)
                modrm = 0xF8 | reg
                code.append(modrm)
            else:
                rex = 0x40
                if reg >= 8:
                    rex |= 0x01
                code.append(rex)
                code.append(0x80)
                modrm = 0xF8 | (reg & 7)
                code.append(modrm)
        code.append(imm & 0xFF)
    return code


# ========== ADD/SUB reg, imm ==========

def encode_add_sub_reg_imm(mnemonic, operands, labels, label_sections, symbols, vaddr_text, vaddr_data, vaddr_bnd=None):
    """ADD/SUB reg, imm — прибавить_непосредственно / вычесть_непосредственно"""
    code = bytearray()
    reg_info = get_reg_info(operands[0])
    reg = reg_info["index"]
    size = reg_info["size"]
    imm = parse_operand(operands[1], labels, label_sections, symbols, vaddr_text, vaddr_data, vaddr_bnd)
    
    op = 0x81
    subop = 0 if mnemonic == "прибавить_непосредственно" else 5
    
    if size == 64:
        rex = 0x48
        if reg >= 8:
            rex |= 0x01
        code.append(rex)
        code.append(op)
        modrm = 0xC0 | (subop << 3) | (reg & 7)
        code.append(modrm)
        code.extend(struct.pack('<i', imm))
    elif size == 32:
        if -128 <= imm <= 127:
            op = 0x83
            rex = 0x40
            if reg >= 8:
                rex |= 0x01
            if rex != 0x40:
                code.append(rex)
            code.append(op)
            modrm = 0xC0 | (subop << 3) | (reg & 7)
            code.append(modrm)
            code.append(imm & 0xFF)
        else:
            rex = 0x40
            if reg >= 8:
                rex |= 0x01
            if rex != 0x40:
                code.append(rex)
            code.append(op)
            modrm = 0xC0 | (subop << 3) | (reg & 7)
            code.append(modrm)
            code.extend(struct.pack('<I', imm & 0xFFFFFFFF))
    elif size == 16:
        code.append(0x66)
        rex = 0x40
        if reg >= 8:
            rex |= 0x01
        if rex != 0x40:
            code.append(rex)
        code.append(op)
        modrm = 0xC0 | (subop << 3) | (reg & 7)
        code.append(modrm)
        code.extend(struct.pack('<H', imm & 0xFFFF))
    return code


# ========== ПЕРЕХОДЫ И ВЫЗОВЫ ==========

def encode_jmp_rel32(operands, labels, label_sections, symbols, vaddr_text, vaddr_data, current_pos, vaddr_bnd=None):
    """JMP rel32 — переход"""
    code = bytearray()
    instr = INSTRUCTIONS["переход"]
    code.extend(instr["opcode"])
    target = parse_operand(operands[0], labels, label_sections, symbols, vaddr_text, vaddr_data, vaddr_bnd)
    offset = target - (vaddr_text + current_pos + 5)
    code.extend(struct.pack('<i', offset))
    return code


def encode_jmp_short(operands, labels, label_sections, symbols, vaddr_text, vaddr_data, current_pos, vaddr_bnd=None):
    """JMP SHORT — короткий_переход"""
    code = bytearray()
    code.append(0xEB)
    target = parse_operand(operands[0], labels, label_sections, symbols, vaddr_text, vaddr_data, vaddr_bnd)
    offset = target - (vaddr_text + current_pos + 2)
    if not (-128 <= offset <= 127):
        raise ValueError(f"Смещение короткого перехода {offset} вне диапазона [-128..127]")
    code.append(offset & 0xFF)
    return code


def encode_jcc_rel32(mnemonic, operands, labels, label_sections, symbols, vaddr_text, vaddr_data, current_pos, vaddr_bnd=None):
    """Jcc rel32 — переход_если_*"""
    code = bytearray()
    instr = INSTRUCTIONS[mnemonic]
    code.extend(instr["opcode"])
    target = parse_operand(operands[0], labels, label_sections, symbols, vaddr_text, vaddr_data, vaddr_bnd)
    offset = target - (vaddr_text + current_pos + 6)
    code.extend(struct.pack('<i', offset))
    return code


def encode_jcc_short(mnemonic, operands, labels, label_sections, symbols, vaddr_text, vaddr_data, current_pos, vaddr_bnd=None):
    """Jcc SHORT — короткий_переход_если_*"""
    code = bytearray()
    instr = INSTRUCTIONS[mnemonic]
    code.extend(instr["opcode"])
    target = parse_operand(operands[0], labels, label_sections, symbols, vaddr_text, vaddr_data, vaddr_bnd)
    offset = target - (vaddr_text + current_pos + 2)
    if not (-128 <= offset <= 127):
        raise ValueError(f"Смещение короткого перехода {offset} вне диапазона [-128..127]")
    code.append(offset & 0xFF)
    return code


def encode_call(operands, labels, label_sections, symbols, vaddr_text, vaddr_data, current_pos, vaddr_bnd=None):
    """CALL rel32 — вызвать"""
    code = bytearray()
    instr = INSTRUCTIONS["вызвать"]
    code.extend(instr["opcode"])
    target = parse_operand(operands[0], labels, label_sections, symbols, vaddr_text, vaddr_data, vaddr_bnd)
    offset = target - (vaddr_text + current_pos + 5)
    code.extend(struct.pack('<i', offset))
    return code


def encode_ret():
    """RET — вернуться"""
    return INSTRUCTIONS["вернуться"]["opcode"]


def encode_loop(operands, labels, label_sections, symbols, vaddr_text, vaddr_data, current_pos, vaddr_bnd=None):
    """LOOP rel8 — цикл"""
    code = bytearray()
    instr = INSTRUCTIONS["цикл"]
    code.extend(instr["opcode"])
    target = parse_operand(operands[0], labels, label_sections, symbols, vaddr_text, vaddr_data, vaddr_bnd)
    offset = target - (vaddr_text + current_pos + 2)
    if not (-128 <= offset <= 127):
        raise ValueError(f"Смещение LOOP {offset} вне диапазона [-128..127]")
    code.append(offset & 0xFF)
    return code


# ========== ДУБЛИКАТЫ ИЗ FIXSIZE ==========
# Эти функции скопированы, чтобы mutsize был автономен.
# При изменении fixsize нужно синхронизировать.

def encode_mov_reg_reg(operands):  # ДУБЛИКАТ
    """MOV reg, reg — переместить"""
    code = bytearray()
    instr = INSTRUCTIONS["переместить"]
    dst_info = get_reg_info(operands[0])
    src_info = get_reg_info(operands[1])
    dst = dst_info["index"]
    src = src_info["index"]
    size = dst_info["size"]
    use_66 = (size == 16)
    use_rex_w = (size == 64)
    rex = 0x40
    if use_rex_w:
        rex |= 0x08
    if src >= 8:
        rex |= 0x04
    if dst >= 8:
        rex |= 0x01
    if dst_info.get("high8") or src_info.get("high8"):
        rex = 0
    if use_66:
        code.append(0x66)
    if rex != 0x40 or use_rex_w:
        code.append(rex)
    code.extend(instr["opcode"][-1:])
    modrm = 0xC0 | ((src & 7) << 3) | (dst & 7)
    code.append(modrm)
    return code


def encode_mov_reg8_imm8(operands):  # ДУБЛИКАТ
    """MOV reg8, imm8 — загрузить_байт"""
    code = bytearray()
    reg_info = get_reg_info(operands[0])
    reg = reg_info["index"]
    imm = int(operands[1]) if operands[1].isdigit() else int(operands[1], 16)
    if reg_info.get("high8"):
        code.append(0xB0 + reg + 4)
    else:
        if reg < 4:
            code.append(0xB0 + reg)
        else:
            rex = 0x40
            if reg >= 8:
                rex |= 0x01
            code.append(rex)
            code.append(0xB0 + (reg & 7))
    code.append(imm & 0xFF)
    return code


def encode_cmp_reg_reg(mnemonic, operands):  # ДУБЛИКАТ
    """CMP/TEST reg, reg — сравнить / проверить"""
    code = bytearray()
    instr = INSTRUCTIONS[mnemonic]
    dst_info = get_reg_info(operands[0])
    src_info = get_reg_info(operands[1])
    dst = dst_info["index"]
    src = src_info["index"]
    size = dst_info["size"]
    use_66 = (size == 16)
    use_rex_w = (size == 64)
    rex = 0x40
    if use_rex_w:
        rex |= 0x08
    if src >= 8:
        rex |= 0x04
    if dst >= 8:
        rex |= 0x01
    if dst_info.get("high8") or src_info.get("high8"):
        rex = 0
    if use_66:
        code.append(0x66)
    if rex != 0x40 or use_rex_w:
        code.append(rex)
    code.extend(instr["opcode"][-1:])
    modrm = 0xC0 | ((src & 7) << 3) | (dst & 7)
    code.append(modrm)
    return code


def encode_add_sub_reg_reg(mnemonic, operands):  # ДУБЛИКАТ
    """ADD/SUB reg, reg — прибавить / вычесть"""
    code = bytearray()
    instr = INSTRUCTIONS[mnemonic]
    dst_info = get_reg_info(operands[0])
    src_info = get_reg_info(operands[1])
    dst = dst_info["index"]
    src = src_info["index"]
    size = dst_info["size"]
    use_66 = (size == 16)
    use_rex_w = (size == 64)
    rex = 0x40
    if use_rex_w:
        rex |= 0x08
    if src >= 8:
        rex |= 0x04
    if dst >= 8:
        rex |= 0x01
    if dst_info.get("high8") or src_info.get("high8"):
        rex = 0
    if use_66:
        code.append(0x66)
    if rex != 0x40 or use_rex_w:
        code.append(rex)
    code.extend(instr["opcode"][-1:])
    modrm = 0xC0 | ((src & 7) << 3) | (dst & 7)
    code.append(modrm)
    return code


def encode_muldiv(mnemonic, operands):  # ДУБЛИКАТ
    """MUL/IMUL/DIV/IDIV"""
    code = bytearray()
    instr = INSTRUCTIONS[mnemonic]
    subop = instr["subop"]
    
    # Получаем индекс регистра-операнда
    if operands:
        reg_info = get_reg_info(operands[0])
        reg = reg_info["index"]
    else:
        reg = 0  # по умолчанию rax
    
    rex = 0x48
    if reg >= 8:
        rex |= 0x01  # REX.B
    
    code.append(rex)
    code.extend(instr["opcode"])
    modrm = 0xC0 | (subop << 3) | (reg & 7)
    code.append(modrm)
    return code


def encode_and_or_xor_reg_reg(mnemonic, operands):  # ДУБЛИКАТ
    """AND/OR/XOR reg, reg"""
    code = bytearray()
    instr = INSTRUCTIONS[mnemonic]
    dst_info = get_reg_info(operands[0])
    src_info = get_reg_info(operands[1])
    dst = dst_info["index"]
    src = src_info["index"]
    size = dst_info["size"]
    use_66 = (size == 16)
    use_rex_w = (size == 64)
    rex = 0x40
    if use_rex_w:
        rex |= 0x08
    if src >= 8:
        rex |= 0x04
    if dst >= 8:
        rex |= 0x01
    if dst_info.get("high8") or src_info.get("high8"):
        rex = 0
    if use_66:
        code.append(0x66)
    if rex != 0x40 or use_rex_w:
        code.append(rex)
    code.extend(instr["opcode"][-1:])
    modrm = 0xC0 | ((src & 7) << 3) | (dst & 7)
    code.append(modrm)
    return code


def encode_not_neg(mnemonic, operands):  # ДУБЛИКАТ
    """NOT/NEG"""
    code = bytearray()
    instr = INSTRUCTIONS[mnemonic]
    reg_info = get_reg_info(operands[0])
    reg = reg_info["index"]
    size = reg_info["size"]
    subop = instr["subop"]
    if size == 64:
        code.append(0x48)
    elif size == 16:
        code.append(0x66)
    if reg >= 8:
        code.append(0x41)
    code.extend(instr["opcode"])
    modrm = 0xC0 | (subop << 3) | (reg & 7)
    code.append(modrm)
    return code


def encode_incdec(mnemonic, operands):  # ДУБЛИКАТ
    """INC/DEC"""
    code = bytearray()
    instr = INSTRUCTIONS[mnemonic]
    reg_info = get_reg_info(operands[0])
    reg = reg_info["index"]
    size = reg_info["size"]
    subop = instr["subop"]
    if size == 64:
        rex = 0x48
        if reg >= 8:
            rex |= 0x01
        code.append(rex)
        code.append(0xFF)
    elif size == 32:
        rex = 0x40
        if reg >= 8:
            rex |= 0x01
        if rex != 0x40:
            code.append(rex)
        code.append(0xFF)
    elif size == 16:
        code.append(0x66)
        rex = 0x40
        if reg >= 8:
            rex |= 0x01
        if rex != 0x40:
            code.append(rex)
        code.append(0xFF)
    elif size == 8:
        if reg_info.get("high8"):
            code.append(0xFE)
        else:
            if reg < 4:
                code.append(0xFE)
            else:
                rex = 0x40
                if reg >= 8:
                    rex |= 0x01
                code.append(rex)
                code.append(0xFE)
        modrm = 0xC0 | (subop << 3) | (reg & 7)
        code.append(modrm)
        return bytes(code)
    modrm = 0xC0 | (subop << 3) | (reg & 7)
    code.append(modrm)
    return bytes(code)


def encode_push_reg(operands):  # ДУБЛИКАТ
    """PUSH reg"""
    code = bytearray()
    reg_info = get_reg_info(operands[0])
    reg = reg_info["index"]
    size = reg_info["size"]
    if size == 64:
        if reg < 8:
            code.append(0x50 + reg)
        else:
            code.append(0x41)
            code.append(0x50 + (reg - 8))
    elif size == 16:
        code.append(0x66)
        if reg < 8:
            code.append(0x50 + reg)
        else:
            code.append(0x41)
            code.append(0x50 + (reg - 8))
    else:
        raise ValueError(f"PUSH не поддерживает {size}-битные регистры")
    return code


def encode_pop_reg(operands):  # ДУБЛИКАТ
    """POP reg"""
    code = bytearray()
    reg_info = get_reg_info(operands[0])
    reg = reg_info["index"]
    size = reg_info["size"]
    if size == 64:
        if reg < 8:
            code.append(0x58 + reg)
        else:
            code.append(0x41)
            if reg<12: # так тесты работают
                code.append(0x58 + (reg - 8)) 
            else:
                code.append(0x58 + (reg - 8))     
    elif size == 16:
        code.append(0x66)
        if reg < 8:
            code.append(0x58 + reg)
        else:
            code.append(0x41)
            code.append(0x58 + (reg - 8))
    else:
        raise ValueError(f"POP не поддерживает {size}-битные регистры")
    return code


def encode_push_imm(operands):  # ДУБЛИКАТ
    """PUSH imm"""
    code = bytearray()
    imm = int(operands[0]) if operands[0].isdigit() else int(operands[0], 16)
    if -128 <= imm <= 127:
        code.append(0x6A)
        code.append(imm & 0xFF)
    else:
        code.append(0x68)
        code.extend(struct.pack('<i', imm))
    return code


def encode_shift_rotate(mnemonic, operands):  # ДУБЛИКАТ
    """SHL/SHR/SAR/ROL/ROR"""
    code = bytearray()
    reg_info = get_reg_info(operands[0])
    reg = reg_info["index"]
    size = reg_info["size"]
    shift = int(operands[1]) if operands[1].isdigit() else int(operands[1], 16)
    if size == 64:
        code.append(0x48)
    code.append(0xC1)
    subop_map = {
        "сдвиг_влево": 4, "сдвиг_вправо": 5,
        "сдвиг_арифметический_вправо": 7,
        "вращать_влево": 0, "вращать_вправо": 1,
    }
    subop = subop_map.get(mnemonic, 0)
    modrm = 0xC0 | (subop << 3) | (reg & 7)
    code.append(modrm)
    code.append(shift & 0xFF)
    return bytes(code)


def encode_syscall():  # ДУБЛИКАТ
    return INSTRUCTIONS["вызов_системы"]["opcode"]


def encode_int(operands):  # ДУБЛИКАТ
    code = bytearray()
    instr = INSTRUCTIONS["прервать"]
    code.extend(instr["opcode"])
    imm = int(operands[0]) if operands[0].isdigit() else int(operands[0], 16)
    code.append(imm & 0xFF)
    return code


def encode_hlt():  # ДУБЛИКАТ
    return INSTRUCTIONS["остановить"]["opcode"]


def encode_int3():  # ДУБЛИКАТ
    return INSTRUCTIONS["отладка"]["opcode"]


def encode_nop():  # ДУБЛИКАТ
    return INSTRUCTIONS["нет_операции"]["opcode"]


def encode_flag_instruction(mnemonic):  # ДУБЛИКАТ
    return INSTRUCTIONS[mnemonic]["opcode"]


def encode_in(operands):  # ДУБЛИКАТ
    code = bytearray()
    instr = INSTRUCTIONS["ввод_байта"]
    code.extend(instr["opcode"])
    port = int(operands[0]) if operands[0].isdigit() else int(operands[0], 16)
    code.append(port & 0xFF)
    return code


def encode_out(operands):  # ДУБЛИКАТ
    code = bytearray()
    instr = INSTRUCTIONS["вывод_байта"]
    code.extend(instr["opcode"])
    port = int(operands[0]) if operands[0].isdigit() else int(operands[0], 16)
    code.append(port & 0xFF)
    return code


def encode_string_instruction(mnemonic):  # ДУБЛИКАТ
    return INSTRUCTIONS[mnemonic]["opcode"]


def encode_cpuid():  # ДУБЛИКАТ
    return INSTRUCTIONS["идентифицировать_процессор"]["opcode"]


def encode_rdtsc():  # ДУБЛИКАТ
    return INSTRUCTIONS["прочитать_счётчик"]["opcode"]


def encode_xchg(operands):  # ДУБЛИКАТ
    """XCHG reg, reg — обменять"""
    code = bytearray()
    instr = INSTRUCTIONS["обменять"]
    reg1_info = get_reg_info(operands[0])
    reg2_info = get_reg_info(operands[1])
    reg1 = reg1_info["index"]
    reg2 = reg2_info["index"]
    rex = 0x48 if reg1_info["size"] == 64 else 0x40
    if reg1 >= 8 or reg2 >= 8:
        rex |= 0x01
        if reg2 >= 8:
            rex |= 0x04
    code.append(rex)
    code.extend(instr["opcode"])
    modrm = 0xC0 | ((reg2 & 7) << 3) | (reg1 & 7)
    code.append(modrm)
    return code


# ========== ГЛАВНЫЙ ДИСПЕТЧЕР ==========

def encode_instruction(mnemonic, operands, labels, label_sections, symbols, vaddr_text, vaddr_data, current_pos, vaddr_bnd=None):
    """
    Главный диспетчер генерации машинного кода.
    По мнемонике выбирает соответствующую функцию генерации.
    
    Аргументы:
    - operands: список строк с операндами (например ['раикс', 'MEM:reg_indirect:рбикс'])
    """
    
    # ----- Инструкции без операндов -----
    if mnemonic == "вызов_системы":
        return encode_syscall()
    elif mnemonic == "нет_операции":
        return encode_nop()
    elif mnemonic == "вернуться":
        return encode_ret()
    elif mnemonic == "остановить":
        return encode_hlt()
    elif mnemonic == "отладка":
        return encode_int3()
    elif mnemonic in ("установить_перенос", "сбросить_перенос", "установить_направление",
                      "сбросить_направление", "втолкнуть_флаги", "вытолкнуть_флаги"):
        return encode_flag_instruction(mnemonic)
    elif mnemonic in ("переместить_байт", "переместить_слово", "сравнить_байты", "сканировать_байт"):
        return encode_string_instruction(mnemonic)
    elif mnemonic == "идентифицировать_процессор":
        return encode_cpuid()
    elif mnemonic == "прочитать_счётчик":
        return encode_rdtsc()
    
    # ----- MOV с памятью -----
    elif mnemonic == "загрузить":
        return encode_mov_reg_mem(operands, labels, label_sections, symbols, vaddr_text, vaddr_data, current_pos, vaddr_bnd)
    elif mnemonic == "сохранить":
        return encode_mov_mem_reg(operands, labels, label_sections, symbols, vaddr_text, vaddr_data, current_pos, vaddr_bnd)
    elif mnemonic == "загрузить_адрес":
        return encode_lea_mem(operands, labels, label_sections, symbols, vaddr_text, vaddr_data, current_pos, vaddr_bnd)
    
    # ----- MOV (разные формы) -----
    elif mnemonic == "переместить_имм":
        return encode_mov_reg_imm(operands, labels, label_sections, symbols, vaddr_text, vaddr_data, vaddr_bnd)
    elif mnemonic == "переместить":
        return encode_mov_reg_reg(operands)
    elif mnemonic == "загрузить_байт":
        return encode_mov_reg8_imm8(operands)
    elif mnemonic == "переместить_с_нулями":
        return encode_movzx(operands, labels, label_sections, symbols, vaddr_text, vaddr_data, vaddr_bnd)
    elif mnemonic == "переместить_со_знаком":
        return encode_movsx(operands, labels, label_sections, symbols, vaddr_text, vaddr_data, vaddr_bnd)
    
    # ----- CMP (сравнение) -----
    elif mnemonic == "сравнить_с":
        return encode_cmp_reg_imm(operands, labels, label_sections, symbols, vaddr_text, vaddr_data, vaddr_bnd)
    elif mnemonic in ("сравнить", "сравнить_байт", "проверить"):
        return encode_cmp_reg_reg(mnemonic, operands)
    
    # ----- ADD/SUB (арифметика) -----
    elif mnemonic in ("прибавить_непосредственно", "вычесть_непосредственно"):
        return encode_add_sub_reg_imm(mnemonic, operands, labels, label_sections, symbols, vaddr_text, vaddr_data, vaddr_bnd)
    elif mnemonic in ("прибавить", "вычесть", "прибавить_байт", "вычесть_байт"):
        return encode_add_sub_reg_reg(mnemonic, operands)
    
    # ----- MUL/DIV -----
    elif mnemonic in ("умножить", "умножить_знаковое", "разделить", "разделить_знаковое"):
        return encode_muldiv(mnemonic, operands)
    
    # ----- AND/OR/XOR -----
    elif mnemonic in ("и", "или", "исключающее_или"):
        return encode_and_or_xor_reg_reg(mnemonic, operands)
    
    # ----- NOT/NEG -----
    elif mnemonic in ("инвертировать", "отрицать"):
        return encode_not_neg(mnemonic, operands)
    
    # ----- INC/DEC -----
    elif mnemonic in ("увеличить", "уменьшить"):
        return encode_incdec(mnemonic, operands)
    
    # ----- Переходы -----
    elif mnemonic == "переход":
        return encode_jmp_rel32(operands, labels, label_sections, symbols, vaddr_text, vaddr_data, current_pos, vaddr_bnd)
    elif mnemonic == "короткий_переход":
        return encode_jmp_short(operands, labels, label_sections, symbols, vaddr_text, vaddr_data, current_pos, vaddr_bnd)
    elif mnemonic in ("переход_если_равно", "переход_если_неравно", "переход_если_меньше",
                      "переход_если_больше", "переход_если_меньше_или_равно", "переход_если_больше_или_равно",
                      "переход_если_перенос", "переход_если_нет_переноса", "переход_если_ноль", "переход_если_не_ноль"):
        return encode_jcc_rel32(mnemonic, operands, labels, label_sections, symbols, vaddr_text, vaddr_data, current_pos, vaddr_bnd)
    elif mnemonic in ("короткий_переход_если_равно", "короткий_переход_если_неравно",
                      "короткий_переход_если_меньше", "короткий_переход_если_больше",
                      "короткий_переход_если_меньше_или_равно", "короткий_переход_если_больше_или_равно",
                      "короткий_переход_если_перенос", "короткий_переход_если_нет_переноса",
                      "короткий_переход_если_ноль", "короткий_переход_если_не_ноль"):
        return encode_jcc_short(mnemonic, operands, labels, label_sections, symbols, vaddr_text, vaddr_data, current_pos, vaddr_bnd)
    
    # ----- CALL/RET/LOOP -----
    elif mnemonic == "вызвать":
        return encode_call(operands, labels, label_sections, symbols, vaddr_text, vaddr_data, current_pos, vaddr_bnd)
    elif mnemonic == "цикл":
        return encode_loop(operands, labels, label_sections, symbols, vaddr_text, vaddr_data, current_pos, vaddr_bnd)
    
    # ----- PUSH/POP -----
    elif mnemonic == "втолкнуть":
        return encode_push_reg(operands)
    elif mnemonic == "вытолкнуть":
        return encode_pop_reg(operands)
    elif mnemonic == "втолкнуть_непосредственно":
        return encode_push_imm(operands)
    
    # ----- Битовые операции -----
    elif mnemonic in ("сдвиг_влево", "сдвиг_вправо", "сдвиг_арифметический_вправо",
                      "вращать_влево", "вращать_вправо"):
        return encode_shift_rotate(mnemonic, operands)
    
    # ----- Ввод-вывод -----
    elif mnemonic == "ввод_байта":
        return encode_in(operands)
    elif mnemonic == "вывод_байта":
        return encode_out(operands)
    
    # ----- Прочие -----
    elif mnemonic == "прервать":
        return encode_int(operands)
    elif mnemonic == "обменять":
        return encode_xchg(operands)
    
    else:
        raise NotImplementedError(f"Инструкция '{mnemonic}' не реализована")