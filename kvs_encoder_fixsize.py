#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Кодировщик инструкций фиксированного размера для КВС
Инструкции, не зависящие от сложной адресации памяти.
Вынесены из kvs_pass2_encoder.py для упрощения поддержки.
"""

import struct
from kvs_data import INSTRUCTIONS, REGISTERS, get_reg_info


# ========== MOV регистр-регистр ==========

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


# ========== MOV reg8, imm8 ==========

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


# ========== CMP/TEST регистр-регистр ==========

def encode_cmp_reg_reg(mnemonic, operands):
    """
    CMP reg, reg - сравнить регистры
    Формат: сравнить <регистр1>, <регистр2>
    Также TEST через проверить.
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


# ========== ADD/SUB регистр-регистр ==========

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


# ========== MUL/IMUL/DIV/IDIV ==========

def encode_muldiv(mnemonic):
    """
    MUL/IMUL/DIV/IDIV - умножение и деление (работают с RAX/RDX)
    Формат: умножить / умножить_знаковое / разделить / разделить_знаковое
    """
    code = bytearray()
    instr = INSTRUCTIONS[mnemonic]
    subop = instr["subop"]
    
    code.append(0x48)
    code.extend(instr["opcode"])
    modrm = 0xC0 | (subop << 3) | 0
    code.append(modrm)
    return code


# ========== AND/OR/XOR регистр-регистр ==========

def encode_and_or_xor_reg_reg(mnemonic, operands):
    """
    AND/OR/XOR reg, reg - логические операции над регистрами
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


# ========== NOT/NEG ==========

def encode_not_neg(mnemonic, operands):
    """
    NOT/NEG - инвертировать/отрицать регистр
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


# ========== INC/DEC ==========

def encode_incdec(mnemonic, operands):
    """
    INC / DEC - инкремент и декремент регистра
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


# ========== Стек (PUSH/POP) ==========

def encode_push_reg(operands):
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


def encode_pop_reg(operands):
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


# ========== Сдвиги и вращения ==========

def encode_shift_rotate(mnemonic, operands):
    """
    SHL/SHR/SAR/ROL/ROR - сдвиги и вращения
    """
    code = bytearray()
    reg_info = get_reg_info(operands[0])
    reg = reg_info["index"]
    size = reg_info["size"]
    shift = int(operands[1]) if operands[1].isdigit() else int(operands[1], 16)
    
    if size == 64:
        code.append(0x48)
    
    code.append(0xC1)
    
    subop_map = {
        "сдвиг_влево": 4,
        "сдвиг_вправо": 5,
        "сдвиг_арифметический_вправо": 7,
        "вращать_влево": 0,
        "вращать_вправо": 1,
    }
    subop = subop_map.get(mnemonic, 0)
    
    modrm = 0xC0 | (subop << 3) | (reg & 7)
    code.append(modrm)
    code.append(shift & 0xFF)
    
    return bytes(code)


# ========== Системные и отладочные ==========

def encode_syscall():
    return INSTRUCTIONS["вызов_системы"]["opcode"]

def encode_int(operands):
    code = bytearray()
    instr = INSTRUCTIONS["прервать"]
    code.extend(instr["opcode"])
    imm = int(operands[0]) if operands[0].isdigit() else int(operands[0], 16)
    code.append(imm & 0xFF)
    return code

def encode_hlt():
    return INSTRUCTIONS["остановить"]["opcode"]

def encode_int3():
    return INSTRUCTIONS["отладка"]["opcode"]

def encode_nop():
    return INSTRUCTIONS["нет_операции"]["opcode"]


# ========== Инструкции работы с флагами ==========

def encode_flag_instruction(mnemonic):
    return INSTRUCTIONS[mnemonic]["opcode"]


# ========== Ввод-вывод ==========

def encode_in(operands):
    code = bytearray()
    instr = INSTRUCTIONS["ввод_байта"]
    code.extend(instr["opcode"])
    port = int(operands[0]) if operands[0].isdigit() else int(operands[0], 16)
    code.append(port & 0xFF)
    return code

def encode_out(operands):
    code = bytearray()
    instr = INSTRUCTIONS["вывод_байта"]
    code.extend(instr["opcode"])
    port = int(operands[0]) if operands[0].isdigit() else int(operands[0], 16)
    code.append(port & 0xFF)
    return code


# ========== Строковые инструкции ==========

def encode_string_instruction(mnemonic):
    return INSTRUCTIONS[mnemonic]["opcode"]


# ========== Идентификация процессора ==========

def encode_cpuid():
    return INSTRUCTIONS["идентифицировать_процессор"]["opcode"]

def encode_rdtsc():
    return INSTRUCTIONS["прочитать_счётчик"]["opcode"]


# ========== XCHG ==========

def encode_xchg(operands):
    """XCHG reg, reg - обменять регистры"""
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