#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Второй проход КВС
Генерирует машинный код и создаёт CSV-файл
"""

import sys
import struct
sys.path.insert(0, '.')
from kvs_data import INSTRUCTIONS, REGISTERS, get_reg_info, PAGE_SIZE, align_up


def unescape_string(s):
    """Преобразует escape-последовательности в реальные символы"""
    result = []
    i = 0
    while i < len(s):
        if s[i] == '\\' and i + 1 < len(s):
            if s[i + 1] == 'n':
                result.append('\n')
            elif s[i + 1] == 't':
                result.append('\t')
            elif s[i + 1] == 'r':
                result.append('\r')
            else:
                result.append(s[i])
                result.append(s[i + 1])
            i += 2
        else:
            result.append(s[i])
            i += 1
    return ''.join(result)


def read_ast(input_file):
    """Читает AST из файла"""
    ast_lines = []
    with open(input_file, 'r', encoding='utf-8') as f:
        for line in f:
            ast_lines.append(line.strip())
    return ast_lines


def read_pass1(input_file):
    """
    Читает результаты первого прохода:
    - PARAM: параметры компоновки (размеры, адреса)
    - LABEL: метки и их позиции
    - SYMBOL: константы
    """
    data = {}
    labels = {}
    label_sections = {}
    symbols = {}
    
    with open(input_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(':')
            if parts[0] == "PARAM":
                key = parts[1]
                value = parts[2]
                if value.isdigit():
                    value = int(value)
                data[key] = value
            elif parts[0] == "LABEL":
                label = parts[1]
                sec = parts[2]
                pos = int(parts[3])
                labels[label] = pos
                label_sections[label] = sec
            elif parts[0] == "SYMBOL":
                name = parts[1]
                value = int(parts[2])
                symbols[name] = value
    
    return data, labels, label_sections, symbols


def parse_operand(operand, labels, label_sections, symbols, vaddr_text, vaddr_data):
    """
    Вычисляет значение операнда.
    Поддерживает:
    - десятичные числа (123)
    - шестнадцатеричные (0x7B)
    - метки (имя_метки)
    - константы (из .константа)
    """
    if operand.isdigit():
        return int(operand)
    if operand.startswith("0x"):
        return int(operand, 16)
    if operand in labels:
        section = label_sections[operand]
        base = vaddr_text if section == ".text" else vaddr_data
        return labels[operand] + base
    if operand in symbols:
        return symbols[operand]
    raise ValueError("Неизвестный операнд: " + operand)


# ========== ГЕНЕРАТОРЫ МАШИННОГО КОДА ДЛЯ КАЖДОЙ ГРУППЫ ИНСТРУКЦИЙ ==========

# ----- 1. Инструкции перемещения данных (MOV, LEA, MOVZX, MOVSX) -----

def encode_mov_reg_imm(operands, labels, label_sections, symbols, vaddr_text, vaddr_data):
    """
    MOV reg, imm - переместить непосредственное значение в регистр
    Формат: переместить_имм <регистр>, <значение|метка|константа>
    """
    code = bytearray()
    reg_info = get_reg_info(operands[0])
    reg = reg_info["index"]
    size = reg_info["size"]
    imm = parse_operand(operands[1], labels, label_sections, symbols, vaddr_text, vaddr_data)

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


def encode_mov_reg_reg(operands):
    """
    MOV reg, reg - переместить данные между регистрами
    Формат: переместить <регистр_назначения>, <регистр_источник>
    """
    code = bytearray()
    instr = INSTRUCTIONS["переместить"]
    dst_info = get_reg_info(operands[0])
    src_info = get_reg_info(operands[1])
    dst = dst_info["index"]
    src = src_info["index"]
    size = dst_info["size"]

    # Формируем REX префикс
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


def encode_mov_reg8_imm8(operands):
    """
    MOV reg8, imm8 - загрузить непосредственный байт в 8-битный регистр
    Формат: загрузить_байт <регистр8>, <байт>
    """
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


def encode_lea(operands, labels, label_sections, symbols, vaddr_text, vaddr_data):
    """
    LEA reg, mem - загрузить эффективный адрес
    Формат: загрузить_адрес <регистр>, <адрес> (упрощённо - пока только метки)
    """
    code = bytearray()
    instr = INSTRUCTIONS["загрузить_адрес"]
    reg_info = get_reg_info(operands[0])
    reg = reg_info["index"]
    addr = parse_operand(operands[1], labels, label_sections, symbols, vaddr_text, vaddr_data)
    
    # Формируем REX префикс
    rex = 0x48 if reg_info["size"] == 64 else 0x40
    if reg >= 8:
        rex |= 0x01
    if rex != 0x40:
        code.append(rex)
    
    code.extend(instr["opcode"][-1:])
    # ModR/M: mod=00 (disp32), reg=reg, r/m=101 (RIP-relative)
    # Упрощённо: используем абсолютный адрес через disp32
    modrm = 0x05 | ((reg & 7) << 3)
    code.append(modrm)
    code.extend(struct.pack('<i', addr))
    return code


def encode_movzx(operands, labels, label_sections, symbols, vaddr_text, vaddr_data):
    """
    MOVZX reg, mem8 - переместить с расширением нулями
    Формат: переместить_с_нулями <регистр>, <адрес_байта>
    """
    code = bytearray()
    instr = INSTRUCTIONS["переместить_с_нулями"]
    reg_info = get_reg_info(operands[0])
    reg = reg_info["index"]
    addr = parse_operand(operands[1], labels, label_sections, symbols, vaddr_text, vaddr_data)
    
    rex = 0x48 if reg_info["size"] == 64 else 0x40
    if reg >= 8:
        rex |= 0x01
    code.append(rex)
    code.extend(instr["opcode"])
    modrm = 0x05 | ((reg & 7) << 3)
    code.append(modrm)
    code.extend(struct.pack('<i', addr))
    return code


def encode_movsx(operands, labels, label_sections, symbols, vaddr_text, vaddr_data):
    """
    MOVSX reg, mem8 - переместить с расширением знака
    Формат: переместить_со_знаком <регистр>, <адрес_байта>
    """
    code = bytearray()
    instr = INSTRUCTIONS["переместить_со_знаком"]
    reg_info = get_reg_info(operands[0])
    reg = reg_info["index"]
    addr = parse_operand(operands[1], labels, label_sections, symbols, vaddr_text, vaddr_data)
    
    rex = 0x48 if reg_info["size"] == 64 else 0x40
    if reg >= 8:
        rex |= 0x01
    code.append(rex)
    code.extend(instr["opcode"])
    modrm = 0x05 | ((reg & 7) << 3)
    code.append(modrm)
    code.extend(struct.pack('<i', addr))
    return code


# ----- 2. Инструкции сравнения (CMP, TEST) -----

def encode_cmp_reg_imm(operands, labels, label_sections, symbols, vaddr_text, vaddr_data):
    """
    CMP reg, imm - сравнить регистр с непосредственным значением
    Формат: сравнить_с <регистр>, <значение|метка|константа>
    """
    code = bytearray()
    reg_info = get_reg_info(operands[0])
    reg = reg_info["index"]
    size = reg_info["size"]
    imm = parse_operand(operands[1], labels, label_sections, symbols, vaddr_text, vaddr_data)

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


def encode_cmp_reg_reg(mnemonic, operands):
    """
    CMP reg, reg - сравнить регистры
    Формат: сравнить <регистр1>, <регистр2>
    """
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


# ----- 3. Арифметические инструкции (ADD, SUB, MUL, DIV) -----

def encode_add_sub_reg_imm(mnemonic, operands, labels, label_sections, symbols, vaddr_text, vaddr_data):
    """
    ADD/SUB reg, imm - прибавить/вычесть непосредственное значение
    Формат: прибавить_непосредственно / вычесть_непосредственно <регистр>, <значение>
    """
    code = bytearray()
    reg_info = get_reg_info(operands[0])
    reg = reg_info["index"]
    size = reg_info["size"]
    imm = parse_operand(operands[1], labels, label_sections, symbols, vaddr_text, vaddr_data)
    
    op_map = {
        "прибавить_непосредственно": 0x81,
        "вычесть_непосредственно": 0x81,
    }
    op = op_map.get(mnemonic, 0x81)
    subop = 0 if mnemonic == "прибавить_непосредственно" else 5  # /0 для ADD, /5 для SUB
    
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
            op = 0x83  # короткая форма
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


def encode_add_sub_reg_reg(mnemonic, operands):
    """
    ADD/SUB reg, reg - сложить/вычесть регистры
    Формат: прибавить / вычесть <регистр_назначения>, <регистр_источник>
    """
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


def encode_muldiv(mnemonic):
    """
    MUL/IMUL/DIV/IDIV - умножение и деление (работают с RAX/RDX)
    Формат: умножить / умножить_знаковое / разделить / разделить_знаковое
    """
    code = bytearray()
    instr = INSTRUCTIONS[mnemonic]
    subop = instr["subop"]
    
    code.append(0x48)  # REX.W для 64-бит
    code.extend(instr["opcode"])
    modrm = 0xC0 | (subop << 3) | 0  # операнд в регистре (например, RBX, RCX)
    code.append(modrm)
    return code


# ----- 4. Логические инструкции (AND, OR, XOR, NOT, NEG) -----

def encode_and_or_xor_reg_reg(mnemonic, operands):
    """
    AND/OR/XOR reg, reg - логические операции над регистрами
    Формат: и / или / исключающее_или <регистр_назначения>, <регистр_источник>
    """
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


def encode_not_neg(mnemonic, operands):
    """
    NOT/NEG - инвертировать/отрицать регистр
    Формат: инвертировать / отрицать <регистр>
    """
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


# ----- 5. Инструкции переходов и вызовов (JMP, Jcc, CALL, RET, LOOP) -----

def encode_jmp_rel32(operands, labels, label_sections, symbols, vaddr_text, vaddr_data, current_pos):
    """
    JMP rel32 - безусловный переход с 32-битным смещением
    Формат: переход <метка>
    """
    code = bytearray()
    instr = INSTRUCTIONS["переход"]
    code.extend(instr["opcode"])
    target = parse_operand(operands[0], labels, label_sections, symbols, vaddr_text, vaddr_data)
    offset = target - (vaddr_text + current_pos + 5)
    code.extend(struct.pack('<i', offset))
    return code


def encode_jmp_short(operands, labels, label_sections, symbols, vaddr_text, vaddr_data, current_pos):
    """
    JMP SHORT - короткий безусловный переход с 8-битным смещением
    Формат: короткий_переход <метка>
    """
    code = bytearray()
    code.append(0xEB)
    target = parse_operand(operands[0], labels, label_sections, symbols, vaddr_text, vaddr_data)
    offset = target - (vaddr_text + current_pos + 2)
    if not (-128 <= offset <= 127):
        raise ValueError(f"Смещение короткого перехода {offset} вне диапазона [-128..127]")
    code.append(offset & 0xFF)
    return code


def encode_jcc_rel32(mnemonic, operands, labels, label_sections, symbols, vaddr_text, vaddr_data, current_pos):
    """
    Jcc rel32 - условный переход с 32-битным смещением
    Формат: переход_если_... <метка>
    """
    code = bytearray()
    instr = INSTRUCTIONS[mnemonic]
    code.extend(instr["opcode"])
    target = parse_operand(operands[0], labels, label_sections, symbols, vaddr_text, vaddr_data)
    offset = target - (vaddr_text + current_pos + 6)
    code.extend(struct.pack('<i', offset))
    return code


def encode_jcc_short(mnemonic, operands, labels, label_sections, symbols, vaddr_text, vaddr_data, current_pos):
    """
    Jcc SHORT - короткий условный переход с 8-битным смещением
    Формат: короткий_переход_если_... <метка>
    """
    code = bytearray()
    instr = INSTRUCTIONS[mnemonic]
    code.extend(instr["opcode"])
    target = parse_operand(operands[0], labels, label_sections, symbols, vaddr_text, vaddr_data)
    offset = target - (vaddr_text + current_pos + 2)
    if not (-128 <= offset <= 127):
        raise ValueError(f"Смещение короткого перехода {offset} вне диапазона [-128..127]")
    code.append(offset & 0xFF)
    return code


def encode_call(operands, labels, label_sections, symbols, vaddr_text, vaddr_data, current_pos):
    """
    CALL rel32 - вызов процедуры
    Формат: вызвать <метка>
    """
    code = bytearray()
    instr = INSTRUCTIONS["вызвать"]
    code.extend(instr["opcode"])
    target = parse_operand(operands[0], labels, label_sections, symbols, vaddr_text, vaddr_data)
    offset = target - (vaddr_text + current_pos + 5)
    code.extend(struct.pack('<i', offset))
    return code


def encode_ret():
    """RET - возврат из процедуры"""
    return INSTRUCTIONS["вернуться"]["opcode"]


def encode_loop(operands, labels, label_sections, symbols, vaddr_text, vaddr_data, current_pos):
    """
    LOOP rel8 - инструкция цикла
    Формат: цикл <метка>
    """
    code = bytearray()
    instr = INSTRUCTIONS["цикл"]
    code.extend(instr["opcode"])
    target = parse_operand(operands[0], labels, label_sections, symbols, vaddr_text, vaddr_data)
    offset = target - (vaddr_text + current_pos + 2)
    if not (-128 <= offset <= 127):
        raise ValueError(f"Смещение LOOP {offset} вне диапазона [-128..127]")
    code.append(offset & 0xFF)
    return code


# ----- 6. Стековые инструкции (PUSH, POP) -----

def encode_push_reg(operands):
    """
    PUSH reg - поместить регистр в стек
    Формат: втолкнуть <регистр>
    """
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


def encode_pop_reg(operands):
    """
    POP reg - извлечь из стека в регистр
    Формат: вытолкнуть <регистр>
    """
    code = bytearray()
    reg_info = get_reg_info(operands[0])
    reg = reg_info["index"]
    size = reg_info["size"]
    
    if size == 64:
        if reg < 8:
            code.append(0x58 + reg)
        else:
            code.append(0x41)
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


def encode_push_imm(operands):
    """
    PUSH imm - поместить непосредственное значение в стек
    Формат: втолкнуть_непосредственно <значение>
    """
    code = bytearray()
    imm = int(operands[0]) if operands[0].isdigit() else int(operands[0], 16)
    
    if -128 <= imm <= 127:
        code.append(0x6A)  # PUSH imm8
        code.append(imm & 0xFF)
    else:
        code.append(0x68)  # PUSH imm32
        code.extend(struct.pack('<i', imm))
    
    return code



# ----- 7. Битовые операции (SHL, SHR, SAR, ROL, ROR) -----

def encode_shift_rotate(mnemonic, operands):
    """
    SHL/SHR/SAR/ROL/ROR - сдвиги и вращения
    Формат: сдвиг_влево <регистр>, <количество>
    """
    code = bytearray()
    reg_info = get_reg_info(operands[0])
    reg = reg_info["index"]
    size = reg_info["size"]
    shift = int(operands[1]) if operands[1].isdigit() else int(operands[1], 16)
    
    # REX.W только для 64-битных регистров
    if size == 64:
        code.append(0x48)
    
    # Опкод C1 для сдвига с imm8
    code.append(0xC1)
    
    # subop в зависимости от типа
    subop_map = {
        "сдвиг_влево": 4,                 # SHL = /4
        "сдвиг_вправо": 5,               # SHR = /5
        "сдвиг_арифметический_вправо": 7, # SAR = /7
        "вращать_влево": 0,              # ROL = /0
        "вращать_вправо": 1,             # ROR = /1
    }
    subop = subop_map.get(mnemonic, 0)
    
    # ModR/M: mod=11, reg=subop, r/m=reg
    modrm = 0xC0 | (subop << 3) | (reg & 7)
    code.append(modrm)
    code.append(shift & 0xFF)
    
    return bytes(code)
# ----- 8. Системные и отладочные инструкции -----

def encode_syscall():
    """SYSCALL - системный вызов"""
    return INSTRUCTIONS["вызов_системы"]["opcode"]


def encode_int(operands):
    """
    INT imm8 - прерывание
    Формат: прервать <номер>
    """
    code = bytearray()
    instr = INSTRUCTIONS["прервать"]
    code.extend(instr["opcode"])
    imm = int(operands[0]) if operands[0].isdigit() else int(operands[0], 16)
    code.append(imm & 0xFF)
    return code


def encode_hlt():
    """HLT - остановить процессор"""
    return INSTRUCTIONS["остановить"]["opcode"]


def encode_int3():
    """INT3 - точка останова (отладка)"""
    return INSTRUCTIONS["отладка"]["opcode"]


def encode_nop():
    """NOP - нет операции"""
    return INSTRUCTIONS["нет_операции"]["opcode"]


# ----- 9. Инструкции работы с флагами -----

def encode_flag_instruction(mnemonic):
    """STC/CLC/STD/CLD/PUSHF/POPF - инструкции работы с флагами"""
    return INSTRUCTIONS[mnemonic]["opcode"]


# ----- 10. Ввод-вывод -----

def encode_in(operands):
    """
    IN imm8 - ввод байта из порта
    Формат: ввод_байта <порт>
    """
    code = bytearray()
    instr = INSTRUCTIONS["ввод_байта"]
    code.extend(instr["opcode"])
    port = int(operands[0]) if operands[0].isdigit() else int(operands[0], 16)
    code.append(port & 0xFF)
    return code


def encode_out(operands):
    """
    OUT imm8 - вывод байта в порт
    Формат: вывод_байта <порт>
    """
    code = bytearray()
    instr = INSTRUCTIONS["вывод_байта"]
    code.extend(instr["opcode"])
    port = int(operands[0]) if operands[0].isdigit() else int(operands[0], 16)
    code.append(port & 0xFF)
    return code


# ----- 11. Строковые инструкции -----

def encode_string_instruction(mnemonic):
    """MOVSB/MOVSW/CMPSB/SCASB - строковые инструкции"""
    return INSTRUCTIONS[mnemonic]["opcode"]


# ----- 12. Инструкции идентификации процессора -----

def encode_cpuid():
    """CPUID - идентификация процессора"""
    return INSTRUCTIONS["идентифицировать_процессор"]["opcode"]


def encode_rdtsc():
    """RDTSC - чтение счётчика времени"""
    return INSTRUCTIONS["прочитать_счётчик"]["opcode"]


# ----- 13. Инструкции с памятью (упрощённые) -----

def encode_xchg(operands):
    """
    XCHG reg, reg - обменять регистры
    Формат: обменять <регистр1>, <регистр2>
    """
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

def encode_instruction(mnemonic, operands, labels, label_sections, symbols, vaddr_text, vaddr_data, current_pos):
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
    
    # ----- MOV (разные формы) -----
    elif mnemonic == "переместить_имм":
        return encode_mov_reg_imm(operands, labels, label_sections, symbols, vaddr_text, vaddr_data)
    elif mnemonic == "переместить":
        return encode_mov_reg_reg(operands)
    elif mnemonic == "загрузить_байт":
        return encode_mov_reg8_imm8(operands)
    elif mnemonic == "загрузить_адрес":
        return encode_lea(operands, labels, label_sections, symbols, vaddr_text, vaddr_data)
    elif mnemonic == "переместить_с_нулями":
        return encode_movzx(operands, labels, label_sections, symbols, vaddr_text, vaddr_data)
    elif mnemonic == "переместить_со_знаком":
        return encode_movsx(operands, labels, label_sections, symbols, vaddr_text, vaddr_data)
    
    # ----- CMP (сравнение) -----
    elif mnemonic == "сравнить_с":
        return encode_cmp_reg_imm(operands, labels, label_sections, symbols, vaddr_text, vaddr_data)
    elif mnemonic in ("сравнить", "сравнить_байт", "проверить"):
        return encode_cmp_reg_reg(mnemonic, operands)
    
    # ----- ADD/SUB (арифметика) -----
    elif mnemonic in ("прибавить_непосредственно", "вычесть_непосредственно"):
        return encode_add_sub_reg_imm(mnemonic, operands, labels, label_sections, symbols, vaddr_text, vaddr_data)
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
        return encode_jmp_rel32(operands, labels, label_sections, symbols, vaddr_text, vaddr_data, current_pos)
    elif mnemonic == "короткий_переход":
        return encode_jmp_short(operands, labels, label_sections, symbols, vaddr_text, vaddr_data, current_pos)
    elif mnemonic in ("переход_если_равно", "переход_если_неравно", "переход_если_меньше",
                      "переход_если_больше", "переход_если_меньше_или_равно", "переход_если_больше_или_равно",
                      "переход_если_перенос", "переход_если_нет_переноса", "переход_если_ноль", "переход_если_не_ноль"):
        return encode_jcc_rel32(mnemonic, operands, labels, label_sections, symbols, vaddr_text, vaddr_data, current_pos)
    elif mnemonic in ("короткий_переход_если_равно", "короткий_переход_если_неравно",
                      "короткий_переход_если_меньше", "короткий_переход_если_больше",
                      "короткий_переход_если_меньше_или_равно", "короткий_переход_если_больше_или_равно",
                      "короткий_переход_если_перенос", "короткий_переход_если_нет_переноса",
                      "короткий_переход_если_ноль", "короткий_переход_если_не_ноль"):
        return encode_jcc_short(mnemonic, operands, labels, label_sections, symbols, vaddr_text, vaddr_data, current_pos)
    
    # ----- CALL/RET/LOOP -----
    elif mnemonic == "вызвать":
        return encode_call(operands, labels, label_sections, symbols, vaddr_text, vaddr_data, current_pos)
    elif mnemonic == "цикл":
        return encode_loop(operands, labels, label_sections, symbols, vaddr_text, vaddr_data, current_pos)
    
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


def encode_incdec(mnemonic, operands):
    """
    INC / DEC - инкремент и декремент регистра
    Формат: увеличить <регистр> / уменьшить <регистр>
    """
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


# ========== ОСНОВНОЙ КЛАСС ВТОРОГО ПРОХОДА ==========

class Pass2:
    def __init__(self, pass1_data, labels, label_sections, symbols):
        self.labels = labels
        self.label_sections = label_sections
        self.symbols = symbols
        self.vaddr_text = pass1_data["vaddr_text"]
        text_size = pass1_data["text_size"]
        self.vaddr_data = align_up(self.vaddr_text + text_size, PAGE_SIZE)
        self.position = {".text": 0, ".data": 0}
        self.current_section = ".text"
        self.csv_lines = []
        self.data_bytes = {".text": bytearray(), ".data": bytearray()}
        
    def get_target_addr(self, mnemonic, operands):
        """Вычисляет целевой адрес для инструкций перехода"""
        jump_instructions = {
            "переход", "короткий_переход", "вызвать", "цикл",
            "переход_если_равно", "переход_если_неравно", "переход_если_меньше",
            "переход_если_больше", "переход_если_меньше_или_равно", "переход_если_больше_или_равно",
            "переход_если_перенос", "переход_если_нет_переноса", "переход_если_ноль", "переход_если_не_ноль",
            "короткий_переход_если_равно", "короткий_переход_если_неравно", "короткий_переход_если_меньше",
            "короткий_переход_если_больше", "короткий_переход_если_меньше_или_равно", "короткий_переход_если_больше_или_равно",
            "короткий_переход_если_перенос", "короткий_переход_если_нет_переноса",
            "короткий_переход_если_ноль", "короткий_переход_если_не_ноль"
        }
        
        try:
            if mnemonic in jump_instructions:
                target = parse_operand(operands[0], self.labels, self.label_sections, 
                                      self.symbols, self.vaddr_text, self.vaddr_data)
                return hex(target)
            elif mnemonic == "переместить_имм" and len(operands) >= 2:
                op_str = operands[1]
                if op_str in self.labels:
                    sec = self.label_sections[op_str]
                    addr = self.labels[op_str] + (self.vaddr_text if sec == ".text" else self.vaddr_data)
                    return hex(addr)
                elif op_str in self.symbols:
                    return hex(self.symbols[op_str])
        except Exception:
            return "ошибка"
        
        return ""
    
    def process_line(self, line):
        """Обрабатывает одну строку AST"""
        parts = line.split(':')
        line_type = parts[0]
        
        if line_type == "DIRECTIVE":
            directive = parts[1]
            if directive == '.текст':
                self.current_section = ".text"
            elif directive == '.данные':
                self.current_section = ".data"
            elif directive in ('.строка_нуль', '.строка'):
                s = parts[3] if len(parts) > 3 else ""
                real_s = unescape_string(s)
                bstring = real_s.encode('utf-8')
                if directive == '.строка_нуль':
                    bstring += b'\x00'
                
                original_cmd = f'{directive} "{s}"'
                start_addr = self.vaddr_data + self.position[".data"]
                
                for i, byte in enumerate(bstring):
                    addr = start_addr + i
                    byte_hex = "{:02X}".format(byte)
                    cmd = original_cmd if i == 0 else ""
                    self.csv_lines.append((hex(addr), byte_hex, "", cmd))
                
                self.data_bytes[".data"] += bstring
                self.position[".data"] += len(bstring)
                
            elif directive == '.байт':
                if len(parts) > 3 and parts[3]:
                    bytes_str = parts[3]
                    byte_values = bytes_str.split(',')
                    original_cmd = f".байт {bytes_str}"
                    start_addr = self.vaddr_data + self.position[".data"]
                    
                    for i, byte_str in enumerate(byte_values):
                        if byte_str.startswith('0x'):
                            val = int(byte_str, 16)
                        elif byte_str.isdigit() or (byte_str.startswith('-') and byte_str[1:].isdigit()):
                            val = int(byte_str)
                        else:
                            continue
                        
                        addr = start_addr + i
                        byte_hex = "{:02X}".format(val & 0xFF)
                        cmd = original_cmd if i == 0 else ""
                        self.csv_lines.append((hex(addr), byte_hex, "", cmd))
                        self.data_bytes[".data"].append(val & 0xFF)
                    
                    self.position[".data"] += len(byte_values)
                    
        elif line_type == "LABEL":
            label_name = parts[1]
            sec = parts[2]
            if label_name in self.labels:
                self.position[sec] = self.labels[label_name]
            
        elif line_type == "INSTR":
            mnemonic = parts[1]
            sec = parts[2]
            
            operands = []
            if len(parts) > 3 and parts[3]:
                operands = parts[3].split(',')
            
            if operands:
                original_cmd = f"{mnemonic} {', '.join(operands)}"
            else:
                original_cmd = mnemonic
            
            current_pos = self.position[sec]
            code = encode_instruction(mnemonic, operands, self.labels, self.label_sections,
                                     self.symbols, self.vaddr_text, self.vaddr_data, current_pos)
            
            target_addr = self.get_target_addr(mnemonic, operands)
            
            start_addr = (self.vaddr_text if sec == ".text" else self.vaddr_data) + current_pos
            
            for i, byte in enumerate(code):
                addr = start_addr + i
                byte_hex = "{:02X}".format(byte)
                cmd = original_cmd if i == 0 else ""
                addr_target = target_addr if i == 0 else ""
                self.csv_lines.append((hex(addr), byte_hex, addr_target, cmd))
            
            self.data_bytes[sec] += code
            self.position[sec] += len(code)
    
    def process_all(self, ast_lines):
        """Обрабатывает все строки AST"""
        for line in ast_lines:
            self.process_line(line)
        return self.csv_lines


def write_csv(csv_lines, output_file):
    """Записывает сгенерированные байты в CSV файл"""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("адрес;байт;целевой_адрес;исходная_команда\n")
        for addr, byte, target, cmd in csv_lines:
            if cmd and (';' in cmd or '\n' in cmd):
                cmd = '"' + cmd.replace('"', '""') + '"'
            f.write(f"{addr};{byte};{target};{cmd}\n")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Использование: python kvs_pass2.py <вход.аст> <вход.проход1> <выход.csv>")
        sys.exit(1)
    
    ast_lines = read_ast(sys.argv[1])
    pass1_data, labels, label_sections, symbols = read_pass1(sys.argv[2])
    
    pass2 = Pass2(pass1_data, labels, label_sections, symbols)
    csv_lines = pass2.process_all(ast_lines)
    write_csv(csv_lines, sys.argv[3])
    
    print(f"Проход 2: {len(csv_lines)} строк CSV записано в {sys.argv[3]}")
    print(f"  .text: {pass2.position['.text']} байт, виртуальный адрес: 0x{pass2.vaddr_text:x}")
    print(f"  .data: {pass2.position['.data']} байт, виртуальный адрес: 0x{pass2.vaddr_data:x}")