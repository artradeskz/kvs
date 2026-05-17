#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Кодировщик инструкций для КВС
Содержит все функции генерации машинного кода.
Фиксированные инструкции вынесены в kvs_pass2_encoder_fixsize.py.
Здесь остаются: parse_operand, parse_memory_operand, инструкции с адресацией, диспетчер.
"""

import struct
import sys
from kvs_data import INSTRUCTIONS, REGISTERS, get_reg_info
from kvs_pass2_encoder_fixsize import (
    encode_mov_reg_reg,
    encode_mov_reg8_imm8,
    encode_cmp_reg_reg,
    encode_add_sub_reg_reg,
    encode_muldiv,
    encode_and_or_xor_reg_reg,
    encode_not_neg,
    encode_incdec,
    encode_push_reg,
    encode_pop_reg,
    encode_push_imm,
    encode_shift_rotate,
    encode_syscall,
    encode_int,
    encode_hlt,
    encode_int3,
    encode_nop,
    encode_flag_instruction,
    encode_in,
    encode_out,
    encode_string_instruction,
    encode_cpuid,
    encode_rdtsc,
    encode_xchg,
)


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
            if vaddr_bnd is not None:
                return labels[operand] + vaddr_bnd
            else:
                return labels[operand] + vaddr_data
        else:
            return labels[operand] + vaddr_text
    if operand in symbols:
        return symbols[operand]
    raise ValueError("Неизвестный операнд: " + operand)


def parse_memory_operand(operand_str, labels, label_sections, vaddr_text, vaddr_data, vaddr_bnd=None):
    """
    Разбирает операнд памяти.
    Возвращает словарь с информацией или None.
    Поддерживает:
    - [число] — абсолютный адрес
    - [метка] — адрес метки (из .data, .text или .бнд)
    - [регистр] — косвенная адресация (TODO)
    """
    if not operand_str.startswith('[') or not operand_str.endswith(']'):
        return None
    
    content = operand_str[1:-1].strip()
    
    # Проверяем, является ли содержимое числом
    if content.isdigit():
        return {
            'type': 'absolute',
            'address': int(content)
        }
    elif content.startswith('0x') or content.startswith('0X'):
        try:
            addr = int(content, 16)
            return {
                'type': 'absolute',
                'address': addr
            }
        except ValueError:
            pass
    
    # Проверяем, является ли содержимое меткой
    if content in labels:
        section = label_sections.get(content, '.data')
        if section == '.text':
            base = vaddr_text
        elif section == '.data':
            base = vaddr_data
        elif section == '.бнд':
            base = vaddr_bnd if vaddr_bnd is not None else vaddr_data
        else:
            base = vaddr_text
        addr = labels[content] + base
        return {
            'type': 'absolute',
            'address': addr
        }
    
    # TODO: другие типы ([reg], [reg+disp], [reg+reg*scale])
    return None


# ========== MOV С ПАМЯТЬЮ ==========

def encode_mov_reg_mem_absolute(reg_info, mem_info, current_pos, vaddr_text):
    """
    Кодирует MOV reg, [addr]
    Используем RIP-relative адресацию: mov reg, [rip + disp32]
    """
    code = bytearray()
    reg = reg_info['index']
    target_addr = mem_info['address']
    
    # Вычисляем смещение относительно RIP
    # Инструкция: REX (1) + opcode (1) + ModRM (1) + disp32 (4) = 7 байт
    rip_at_end = vaddr_text + current_pos + 7
    offset = target_addr - rip_at_end
    
    # REX префикс (W=1 для 64-бит, R=бит для reg)
    rex = 0x48 if reg_info['size'] == 64 else 0x40
    if reg >= 8:
        rex |= 0x01  # REX.R
    code.append(rex)
    
    # Opcode для MOV reg, mem (8B)
    code.append(0x8B)
    
    # ModR/M: mod=00 (disp32), reg=reg, r/m=101 (RIP-relative)
    modrm = 0x05 | ((reg & 7) << 3)
    code.append(modrm)
    
    # disp32 (смещение относительно RIP)
    code.extend(struct.pack('<i', offset))
    
    return code


def encode_mov_mem_reg_absolute(reg_info, mem_info, current_pos, vaddr_text):
    """
    Кодирует MOV [addr], reg
    Используем RIP-relative адресацию: mov [rip + disp32], reg
    """
    code = bytearray()
    reg = reg_info['index']
    target_addr = mem_info['address']
    
    # Вычисляем смещение относительно RIP
    rip_at_end = vaddr_text + current_pos + 7
    offset = target_addr - rip_at_end
    
    # REX префикс
    rex = 0x48 if reg_info['size'] == 64 else 0x40
    if reg >= 8:
        rex |= 0x01
    code.append(rex)
    
    # Opcode для MOV mem, reg (89)
    code.append(0x89)
    
    # ModR/M: mod=00, reg=reg, r/m=101
    modrm = 0x05 | ((reg & 7) << 3)
    code.append(modrm)
    
    # disp32
    code.extend(struct.pack('<i', offset))
    
    return code


def encode_mov_reg_mem(operands, labels, label_sections, symbols, vaddr_text, vaddr_data, current_pos, vaddr_bnd=None):
    """
    MOV reg, mem - загрузить из памяти в регистр
    Формат: загрузить <регистр>, [<адрес>]
    """
    reg_info = get_reg_info(operands[0])
    mem_operand = operands[1]
    
    mem_info = parse_memory_operand(mem_operand, labels, label_sections, vaddr_text, vaddr_data, vaddr_bnd)
    if mem_info and mem_info['type'] == 'absolute':
        return encode_mov_reg_mem_absolute(reg_info, mem_info, current_pos, vaddr_text)
    
    print(f"Предупреждение: сложная адресация '{mem_operand}' пока не поддерживается", file=sys.stderr)
    return b'\x90' * 3


def encode_mov_mem_reg(operands, labels, label_sections, symbols, vaddr_text, vaddr_data, current_pos, vaddr_bnd=None):
    """
    MOV mem, reg - сохранить из регистра в память
    Формат: сохранить [<адрес>], <регистр>
    """
    mem_operand = operands[0]
    reg_info = get_reg_info(operands[1])
    
    mem_info = parse_memory_operand(mem_operand, labels, label_sections, vaddr_text, vaddr_data, vaddr_bnd)
    if mem_info and mem_info['type'] == 'absolute':
        return encode_mov_mem_reg_absolute(reg_info, mem_info, current_pos, vaddr_text)
    
    print(f"Предупреждение: сложная адресация '{mem_operand}' пока не поддерживается", file=sys.stderr)
    return b'\x90' * 3


def encode_lea_mem(operands, labels, label_sections, symbols, vaddr_text, vaddr_data, current_pos, vaddr_bnd=None):
    """
    LEA reg, mem - загрузить эффективный адрес
    Формат: загрузить_адрес <регистр>, [<адрес>]
    """
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
        
        code.append(0x8D)  # LEA opcode
        modrm = 0x05 | ((reg & 7) << 3)
        code.append(modrm)
        code.extend(struct.pack('<i', offset))
        return code
    
    print(f"Предупреждение: LEA с адресацией '{mem_operand}' пока не поддерживается", file=sys.stderr)
    return b'\x90' * 3


# ========== MOV reg, imm (зависит от parse_operand) ==========

def encode_mov_reg_imm(operands, labels, label_sections, symbols, vaddr_text, vaddr_data, vaddr_bnd=None):
    """
    MOV reg, imm - переместить непосредственное значение в регистр
    Формат: переместить_имм <регистр>, <значение|метка|константа>
    """
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


# ========== MOVZX/MOVSX (зависят от parse_operand) ==========

def encode_movzx(operands, labels, label_sections, symbols, vaddr_text, vaddr_data, vaddr_bnd=None):
    """
    MOVZX reg, mem8 - переместить с расширением нулями
    Формат: переместить_с_нулями <регистр>, <адрес_байта>
    """
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
    """
    MOVSX reg, mem8 - переместить с расширением знака
    Формат: переместить_со_знаком <регистр>, <адрес_байта>
    """
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


# ========== CMP reg, imm (зависит от parse_operand) ==========

def encode_cmp_reg_imm(operands, labels, label_sections, symbols, vaddr_text, vaddr_data, vaddr_bnd=None):
    """
    CMP reg, imm - сравнить регистр с непосредственным значением
    Формат: сравнить_с <регистр>, <значение|метка|константа>
    """
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


# ========== ADD/SUB reg, imm (зависит от parse_operand) ==========

def encode_add_sub_reg_imm(mnemonic, operands, labels, label_sections, symbols, vaddr_text, vaddr_data, vaddr_bnd=None):
    """
    ADD/SUB reg, imm - прибавить/вычесть непосредственное значение
    Формат: прибавить_непосредственно / вычесть_непосредственно <регистр>, <значение>
    """
    code = bytearray()
    reg_info = get_reg_info(operands[0])
    reg = reg_info["index"]
    size = reg_info["size"]
    imm = parse_operand(operands[1], labels, label_sections, symbols, vaddr_text, vaddr_data, vaddr_bnd)
    
    op_map = {
        "прибавить_непосредственно": 0x81,
        "вычесть_непосредственно": 0x81,
    }
    op = op_map.get(mnemonic, 0x81)
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


# ========== ПЕРЕХОДЫ И ВЫЗОВЫ (зависят от parse_operand) ==========

def encode_jmp_rel32(operands, labels, label_sections, symbols, vaddr_text, vaddr_data, current_pos, vaddr_bnd=None):
    """
    JMP rel32 - безусловный переход с 32-битным смещением
    """
    code = bytearray()
    instr = INSTRUCTIONS["переход"]
    code.extend(instr["opcode"])
    target = parse_operand(operands[0], labels, label_sections, symbols, vaddr_text, vaddr_data, vaddr_bnd)
    offset = target - (vaddr_text + current_pos + 5)
    code.extend(struct.pack('<i', offset))
    return code


def encode_jmp_short(operands, labels, label_sections, symbols, vaddr_text, vaddr_data, current_pos, vaddr_bnd=None):
    """
    JMP SHORT - короткий безусловный переход с 8-битным смещением
    """
    code = bytearray()
    code.append(0xEB)
    target = parse_operand(operands[0], labels, label_sections, symbols, vaddr_text, vaddr_data, vaddr_bnd)
    offset = target - (vaddr_text + current_pos + 2)
    if not (-128 <= offset <= 127):
        raise ValueError(f"Смещение короткого перехода {offset} вне диапазона [-128..127]")
    code.append(offset & 0xFF)
    return code


def encode_jcc_rel32(mnemonic, operands, labels, label_sections, symbols, vaddr_text, vaddr_data, current_pos, vaddr_bnd=None):
    """
    Jcc rel32 - условный переход с 32-битным смещением
    """
    code = bytearray()
    instr = INSTRUCTIONS[mnemonic]
    code.extend(instr["opcode"])
    target = parse_operand(operands[0], labels, label_sections, symbols, vaddr_text, vaddr_data, vaddr_bnd)
    offset = target - (vaddr_text + current_pos + 6)
    code.extend(struct.pack('<i', offset))
    return code


def encode_jcc_short(mnemonic, operands, labels, label_sections, symbols, vaddr_text, vaddr_data, current_pos, vaddr_bnd=None):
    """
    Jcc SHORT - короткий условный переход с 8-битным смещением
    """
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
    """
    CALL rel32 - вызов процедуры
    """
    code = bytearray()
    instr = INSTRUCTIONS["вызвать"]
    code.extend(instr["opcode"])
    target = parse_operand(operands[0], labels, label_sections, symbols, vaddr_text, vaddr_data, vaddr_bnd)
    offset = target - (vaddr_text + current_pos + 5)
    code.extend(struct.pack('<i', offset))
    return code


def encode_ret():
    """RET - возврат из процедуры"""
    return INSTRUCTIONS["вернуться"]["opcode"]


def encode_loop(operands, labels, label_sections, symbols, vaddr_text, vaddr_data, current_pos, vaddr_bnd=None):
    """
    LOOP rel8 - инструкция цикла
    """
    code = bytearray()
    instr = INSTRUCTIONS["цикл"]
    code.extend(instr["opcode"])
    target = parse_operand(operands[0], labels, label_sections, symbols, vaddr_text, vaddr_data, vaddr_bnd)
    offset = target - (vaddr_text + current_pos + 2)
    if not (-128 <= offset <= 127):
        raise ValueError(f"Смещение LOOP {offset} вне диапазона [-128..127]")
    code.append(offset & 0xFF)
    return code


# ========== ГЛАВНЫЙ ДИСПЕТЧЕР ==========

def encode_instruction(mnemonic, operands, labels, label_sections, symbols, vaddr_text, vaddr_data, current_pos, vaddr_bnd=None):
    """
    Главный диспетчер генерации машинного кода.
    По мнемонике выбирает соответствующую функцию генерации.
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
        return encode_muldiv(mnemonic)
    
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