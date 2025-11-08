#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
kvs_5.py
КВС - язык программирования  
без использования re
(расширенная версия с короткими переходами и полными регистрами)
"""

import sys
import struct

# Глобальная переменная для имени исходного файла
source_filename = ""

def safe_close(f):
    if f is not None:
        f.close()

# === Глобальные данные ===
INSTRUCTIONS = {
    "переместить_имм": {"code": None, "type": "reg_imm"},
    "сравнить_с": {"code": None, "type": "cmp_reg_imm"},  
    "переход_если_неравно": {"code": b"\x0F\x85", "type": "jcc"},
    "вызов_системы": {"code": b"\x0F\x05", "type": "none"},
    "переход": {"code": b"\xE9", "type": "jmp"},
    # === Короткие переходы ===
    "короткий_переход": {"code": b"\xEB", "type": "short_jmp"},
    "короткий_переход_если_равно"           : {"code": b"\x74", "type": "short_jcc"},
    "короткий_переход_если_неравно"         : {"code": b"\x75", "type": "short_jcc"},
    "короткий_переход_если_меньше"          : {"code": b"\x7C", "type": "short_jcc"},
    "короткий_переход_если_больше"          : {"code": b"\x7F", "type": "short_jcc"},
    "короткий_переход_если_меньше_или_равно": {"code": b"\x7E", "type": "short_jcc"},
    "короткий_переход_если_больше_или_равно": {"code": b"\x7D", "type": "short_jcc"},
    "короткий_переход_если_перенос"         : {"code": b"\x72", "type": "short_jcc"},
    "короткий_переход_если_нет_переноса"    : {"code": b"\x73", "type": "short_jcc"},
    "короткий_переход_если_ноль"            : {"code": b"\x74", "type": "short_jcc"},
    "короткий_переход_если_не_ноль"         : {"code": b"\x75", "type": "short_jcc"},
    # === Новые команды для флагов ===
    "сравнить": {"code": b"\x48\x39", "type": "cmp_reg_reg"},
    "проверить": {"code": b"\x48\x85", "type": "test_reg_reg"},
    "вычесть": {"code": b"\x48\x29", "type": "sub_reg_reg"},
    "прибавить": {"code": b"\x48\x01", "type": "add_reg_reg"},
    "увеличить": {"code": b"\xFF", "subop": 0, "type": "incdec"},
    "уменьшить": {"code": b"\xFF", "subop": 1, "type": "incdec"},
}

REGISTERS = {
    # 64-битные
    "раикс": 0, "рсикс": 1, "рдикс": 2, "рбикс": 3,
    "рсипи": 4, "рбипи": 5, "рсиай": 6, "рдиай": 7,
    "р8": 8, "р9": 9, "р10": 10, "р11": 11,
    "р12": 12, "р13": 13, "р14": 14, "р15": 15,
    # 32-битные
    "еаикс": 0, "есикс": 1, "едикс": 2, "ебикс": 3,
    "есипи": 4, "ебипи": 5, "есиай": 6, "едиай": 7,
    "р8д": 8, "р9д": 9, "р10д": 10, "р11д": 11,
    "р12д": 12, "р13д": 13, "р14д": 14, "р15д": 15,
    # 16-битные
    "аикс": 0, "сикс": 1, "дикс": 2, "бикс": 3,
    "эсп": 4, "бипи": 5, "эс": 6, "ди": 7,
    "р8в": 8, "р9в": 9, "р10в": 10, "р11в": 11,
    "р12в": 12, "р13в": 13, "р14в": 14, "р15в": 15,
    # 8-битные младшие
    "ал": 0, "кл": 1, "дл": 2, "бл": 3,
    "спл": 4, "бпл": 5, "сил": 6, "дил": 7,
    "р8б": 8, "р9б": 9, "р10б": 10, "р11б": 11,
    "р12б": 12, "р13б": 13, "р14б": 14, "р15б": 15,
    # 8-битные старшие (только первые 4)
    "аш": 0, "чш": 1, "дш": 2, "бш": 3,
}

# Глобальное состояние ассемблера
labels = {}
label_sections = {}
symbols = {}
sections = {".text": bytearray(), ".data": bytearray()}
current_section = ".text"
entry_point = "_start"
position = {".text": 0, ".data": 0}
pass_num = 0

# === Для логирования ===
log_entries = []

# === ELF layout ===
PAGE_SIZE = 0x1000
elf_base_vaddr = 0x400000
text_vaddr_base = 0x401000
data_vaddr_base = 0x402000

text_size = 0
data_size = 0
comment_size = 0
offset_text = 0
offset_data = 0
offset_comment = 0
shstrtab_offset = 0
shdr_offset = 0
vaddr_text = 0
vaddr_data = 0

def align_up(x, align):
    return (x + align - 1) & ~(align - 1)

def get_reg_info(reg_name):
    if reg_name in ["аш", "чш", "дш", "бш"]:
        return {"size": 8, "index": REGISTERS[reg_name], "high8": True}
    elif reg_name.endswith(("б", "л")) or reg_name in ["ал", "кл", "дл", "бл", "спл", "бпл", "сил", "дил"]:
        return {"size": 8, "index": REGISTERS[reg_name], "high8": False}
    elif reg_name.endswith("в") or reg_name in ["аикс", "сикс", "дикс", "бикс", "эсп", "бипи", "эс", "ди"]:
        return {"size": 16, "index": REGISTERS[reg_name]}
    elif reg_name.endswith("д") or reg_name in ["еаикс", "есикс", "едикс", "ебикс", "есипи", "ебипи", "есиай", "едиай"]:
        return {"size": 32, "index": REGISTERS[reg_name]}
    else:
        return {"size": 64, "index": REGISTERS[reg_name]}

# === Функции формирования ошибок ===
def make_error_msg(line_num, line_text, detail):
    return "Ошибка в файле " + source_filename + ", строка " + str(line_num) + ":\n    " + line_text + "\n" + detail

def error_invalid_operand_count(mnemonic, expected, got):
    return "Инструкция '" + mnemonic + "':\n    ожидается " + str(expected) + " операнд(а/ов), получено: " + str(got)

def error_unknown_mnemonic(mnemonic):
    return "Неизвестная инструкция: '" + mnemonic + "'"

def error_invalid_register(op_name, reg_name, mnemonic):
    return ("Инструкция '" + mnemonic + "':\n    операнд '" + op_name + "' = '" + reg_name +
            "' не является допустимым регистром.\n    Допустимые регистры: " + ", ".join(list(REGISTERS.keys())))

def error_invalid_number_format(s):
    return "Недопустимый формат числа: '" + s + "'"

def error_unknown_directive(word):
    return "Неизвестная директива: '" + word + "'"

def error_missing_label(label):
    return "Метка не найдена: '" + label + "'"

def error_unexpected_string_in_byte():
    return ".байт требует числовые значения, не строки"

def error_unterminated_string():
    return "Незакрытая кавычка в строке"

# === Лексер ===
def tokenize_line(line):
    semi = line.find(';')
    if semi != -1:
        line = line[:semi]
    line = line.rstrip()
    if not line:
        return []
    tokens = []
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if ch.isspace():
            i += 1
            continue
        if ch == '"':
            i += 1
            s = ''
            while i < n and line[i] != '"':
                if line[i] == '\\' and i + 1 < n:
                    i += 1
                    esc = line[i]
                    if esc == 'n':
                        s += '\n'
                    elif esc == 't':
                        s += '\t'
                    elif esc == '"':
                        s += '"'
                    elif esc == '\\':
                        s += '\\'
                    else:
                        s += '\\' + esc
                    i += 1
                else:
                    s += line[i]
                    i += 1
            if i >= n:
                raise ValueError(error_unterminated_string())
            i += 1
            tokens.append(('string', s))
            continue
        if ch == ',':
            tokens.append(('comma', ','))
            i += 1
            continue
        if ch == ':':
            tokens.append(('colon', ':'))
            i += 1
            continue
        j = i
        while j < n and not (line[j].isspace() or line[j] in ',:;'):
            j += 1
        word = line[i:j]
        if word:
            tokens.append(('word', word))
        i = j
    return tokens

# === Парсинг ===
def parse_operand(operand):
    if operand.isdigit():
        return int(operand)
    if operand.startswith("0x"):
        return int(operand, 16)
    if operand in labels:
        section = label_sections[operand]
        if pass_num == 2:
            base = vaddr_text if section == ".text" else vaddr_data
            return labels[operand] + base
        else:
            return labels[operand]
    if operand in symbols:
        return symbols[operand]
    raise ValueError("Неизвестный операнд: " + operand)

def encode_instruction(mnemonic, operands, line_num, line_text):
    instr = INSTRUCTIONS[mnemonic]
    code = bytearray()
    itype = instr["type"]

    if itype == "none":
        code.extend(instr["code"])

    elif itype == "reg_imm":
        if len(operands) != 2:
            raise ValueError(error_invalid_operand_count(mnemonic, 2, len(operands)))
        reg_info = get_reg_info(operands[0])
        if reg_info is None:
            raise ValueError(error_invalid_register("назначения", operands[0], mnemonic))
        reg = reg_info["index"]
        size = reg_info["size"]
        imm = parse_operand(operands[1])

        if size == 64:
            if 0 <= reg <= 7:
                code.extend(b'\x48')
                code.append(0xB8 + reg)
                code.extend(struct.pack('<Q', imm))
            elif 8 <= reg <= 15:
                code.extend(b'\x49')
                code.append(0xB8 + (reg - 8))
                code.extend(struct.pack('<Q', imm))
            else:
                raise ValueError("Недопустимый регистр в '" + mnemonic + "'")
        elif size == 32:
            if -0x80000000 <= imm <= 0x7FFFFFFF:
                rex = 0x40
                if reg >= 8:
                    rex |= 0x01
                if rex != 0x40:
                    code.append(rex)
                code.append(0xC7)
                modrm = 0xC0 | (reg & 7)
                code.append(modrm)
                code.extend(struct.pack('<I', imm & 0xFFFFFFFF))
            else:
                raise ValueError("32-битное значение вне диапазона")
        elif size == 16:
            if 0 <= imm <= 0xFFFF:
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
            else:
                raise ValueError("16-битное значение вне диапазона")
        elif size == 8:
            if not (0 <= imm <= 255):
                raise ValueError("8-битное значение вне диапазона 0–255")
            if reg_info.get("high8"):
                if reg < 4:
                    code.append(0xB0 + reg + 4)
                    code.append(imm & 0xFF)
                else:
                    raise ValueError("Старшие байты только для первых 4 регистров")
            else:
                if reg < 4:
                    code.append(0xB0 + reg)
                    code.append(imm & 0xFF)
                else:
                    rex = 0x40
                    if reg >= 8:
                        rex |= 0x01
                    code.append(rex)
                    code.append(0xB0 + (reg & 7))
                    code.append(imm & 0xFF)
        else:
            raise ValueError("Неподдерживаемый размер регистра")

    elif itype == "cmp_reg_imm":
        if len(operands) != 2:
            raise ValueError(error_invalid_operand_count(mnemonic, 2, len(operands)))
        reg_info = get_reg_info(operands[0])
        if reg_info is None:
            raise ValueError(error_invalid_register("регистра", operands[0], mnemonic))
        reg = reg_info["index"]
        size = reg_info["size"]
        imm = parse_operand(operands[1])

        if size == 64:
            if -128 <= imm <= 127:
                rex = 0x48
                if reg >= 8:
                    rex |= 0x01
                code.append(rex)
                code.append(0x83)
                modrm = 0xF8 | (reg & 7)
                code.append(modrm)
                code.append(imm & 0xFF)
            elif -0x80000000 <= imm <= 0x7FFFFFFF:
                rex = 0x48
                if reg >= 8:
                    rex |= 0x01
                code.append(rex)
                code.append(0x81)
                modrm = 0xF8 | (reg & 7)
                code.append(modrm)
                code.extend(struct.pack('<i', imm))
            else:
                raise ValueError("Непосредственное значение слишком велико для сравнения: " + str(imm))
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
            elif -0x80000000 <= imm <= 0x7FFFFFFF:
                rex = 0x40
                if reg >= 8:
                    rex |= 0x01
                if rex != 0x40:
                    code.append(rex)
                code.append(0x81)
                modrm = 0xF8 | (reg & 7)
                code.append(modrm)
                code.extend(struct.pack('<I', imm & 0xFFFFFFFF))
            else:
                raise ValueError("32-битное непосредственное значение вне диапазона")
        elif size == 16:
            if -128 <= imm <= 127:
                code.append(0x66)
                rex = 0x40
                if reg >= 8:
                    rex |= 0x01
                if rex != 0x40:
                    code.append(rex)
                code.append(0x83)
                modrm = 0xF8 | (reg & 7)
                code.append(modrm)
                code.append(imm & 0xFF)
            elif 0 <= imm <= 0xFFFF:
                code.append(0x66)
                rex = 0x40
                if reg >= 8:
                    rex |= 0x01
                if rex != 0x40:
                    code.append(rex)
                code.append(0x81)
                modrm = 0xF8 | (reg & 7)
                code.append(modrm)
                code.append(imm & 0xFF)
                code.append((imm >> 8) & 0xFF)
            else:
                raise ValueError("16-битное непосредственное значение вне диапазона")
        elif size == 8:
            if not (0 <= imm <= 255):
                raise ValueError("8-битное значение вне диапазона 0–255")
            if reg_info.get("high8"):
                if reg < 4:
                    code.append(0x80)
                    modrm = 0xF8 | reg
                    code.append(modrm)
                    code.append(imm & 0xFF)
                else:
                    raise ValueError("Старшие байты только для первых 4 регистров")
            else:
                if reg < 4:
                    code.append(0x80)
                    modrm = 0xF8 | reg
                    code.append(modrm)
                    code.append(imm & 0xFF)
                else:
                    rex = 0x40
                    if reg >= 8:
                        rex |= 0x01
                    code.append(rex)
                    code.append(0x80)
                    modrm = 0xF8 | (reg & 7)
                    code.append(modrm)
                    code.append(imm & 0xFF)
        else:
            raise ValueError("Неподдерживаемый размер регистра")

    elif itype == "jmp":
        if len(operands) != 1:
            raise ValueError(error_invalid_operand_count(mnemonic, 1, len(operands)))
        code.extend(instr["code"])
        target = parse_operand(operands[0])
        current_addr = vaddr_text + position[".text"]
        offset = target - (current_addr + 5)
        if offset < -0x80000000 or offset > 0x7FFFFFFF:
            raise ValueError("Цель слишком далеко для 32-битного смещения в инструкции '" + mnemonic + "': " + str(offset))
        code.extend(struct.pack('<i', offset))

    elif itype == "jcc":
        if len(operands) != 1:
            raise ValueError(error_invalid_operand_count(mnemonic, 1, len(operands)))
        code.extend(instr["code"])
        target = parse_operand(operands[0])
        current_addr = vaddr_text + position[".text"]
        offset = target - (current_addr + 6)
        if offset < -0x80000000 or offset > 0x7FFFFFFF:
            raise ValueError("Цель условного перехода слишком далеко: " + str(offset))
        code.extend(struct.pack('<i', offset))

    elif itype == "short_jmp":
        if len(operands) != 1:
            raise ValueError(error_invalid_operand_count(mnemonic, 1, len(operands)))
        target = parse_operand(operands[0])
        current_addr = vaddr_text + position[".text"]
        offset = target - (current_addr + 2)
        if offset < -128 or offset > 127:
            raise ValueError("Цель слишком далеко для короткого перехода: " + str(offset))
        code.append(0xEB)
        code.append(offset & 0xFF)

    elif itype == "short_jcc":
        if len(operands) != 1:
            raise ValueError(error_invalid_operand_count(mnemonic, 1, len(operands)))
        code.extend(instr["code"])
        target = parse_operand(operands[0])
        current_addr = vaddr_text + position[".text"]
        offset = target - (current_addr + 2)
        if offset < -128 or offset > 127:
            raise ValueError("Цель слишком далеко для короткого условного перехода: " + str(offset))
        code.append(offset & 0xFF)

    elif itype in ("cmp_reg_reg", "test_reg_reg", "add_reg_reg", "sub_reg_reg"):
        if len(operands) != 2:
            raise ValueError(error_invalid_operand_count(mnemonic, 2, len(operands)))
        dst_info = get_reg_info(operands[0])
        src_info = get_reg_info(operands[1])
        if dst_info is None:
            raise ValueError(error_invalid_register("назначения", operands[0], mnemonic))
        if src_info is None:
            raise ValueError(error_invalid_register("источника", operands[1], mnemonic))
        dst = dst_info["index"]
        src = src_info["index"]
        size = dst_info["size"]
        if size != src_info["size"]:
            raise ValueError("Размеры операндов не совпадают в инструкции '" + mnemonic + "'")

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
            if rex != 0x40:
                raise ValueError("Старшие байты несовместимы с REX")
            rex = 0

        op_map = {
            "cmp_reg_reg": 0x39,
            "test_reg_reg": 0x85,
            "add_reg_reg": 0x01,
            "sub_reg_reg": 0x29,
        }
        op = op_map[itype]

        if use_66:
            code.append(0x66)
        if rex != 0x40 or use_rex_w:
            code.append(rex)
        code.append(op)
        modrm = 0xC0 | ((src & 7) << 3) | (dst & 7)
        code.append(modrm)

    elif itype == "incdec":
        if len(operands) != 1:
            raise ValueError(error_invalid_operand_count(mnemonic, 1, len(operands)))
        reg_info = get_reg_info(operands[0])
        if reg_info is None:
            raise ValueError(error_invalid_register("регистра", operands[0], mnemonic))
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
                if reg < 4:
                    code.append(0xFE)
                else:
                    raise ValueError("Старшие байты только для первых 4 регистров")
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
        else:
            raise ValueError("Неподдерживаемый размер регистра")

        modrm = 0xC0 | (subop << 3) | (reg & 7)
        code.append(modrm)

    else:
        raise ValueError("Неизвестный тип инструкции: " + itype)

    return bytes(code)



def parse_instruction_or_directive(tokens, line_num, line_text):
    global current_section, entry_point, symbols # Не забудьте добавить symbols в global
    first = tokens[0]
    if first[0] != 'word':
        raise ValueError("Ожидалось слово, получено: " + str(first))
    word = first[1]
    if word.startswith('.'):
        if word == '.текст':
            current_section = ".text"
        elif word == '.данные':
            current_section = ".data"
        elif word == '.глобал':
            if len(tokens) < 2 or tokens[1][0] != 'word':
                raise ValueError(".глобал требует имя метки")
            entry_point = tokens[1][1]
        elif word == '.строка_нуль' or word == '.строка':
            if len(tokens) < 2 or tokens[1][0] != 'string':
                raise ValueError(word + " требует строку в кавычках")
            if current_section != ".data":
                raise ValueError("Строки разрешены только в секции .data")
            s = tokens[1][1]
            bstring = s.encode('utf-8')
            add_null = (word == '.строка_нуль')
            size = len(bstring) + (1 if add_null else 0)
            if pass_num == 1:
                position[".data"] += size
            elif pass_num == 2:
                sections[".data"] += bstring
                if add_null:
                    sections[".data"] += b'\x00'
                position[".data"] += size
        # === НОВАЯ ДИРЕКТИВА .КОНСТАНТА ===
        elif word == '.константа':
            if len(tokens) < 3 or tokens[1][0] != 'word' or tokens[2][0] != 'word' or tokens[2][1] != '=' or len(tokens) < 4 or tokens[3][0] not in ('word', 'string'): # Проверяем формат: .константа имя = значение
                 raise ValueError(".константа требует формат: .константа <имя> = <значение>")
            const_name = tokens[1][1]
            const_value_str = tokens[3][1]
            try:
                # Попробуем распарсить значение как число или символ (если это метка)
                const_value = parse_operand(const_value_str)
            except ValueError:
                raise ValueError("Невозможно распознать значение константы '" + const_value_str + "'")

            # Записываем в глобальный словарь символов
            symbols[const_name] = const_value
            # Директива .константа не добавляет байты в секцию
            return
        # === КОНЕЦ НОВОЙ ДИРЕКТИВЫ ===
        else:
            raise ValueError(error_unknown_directive(word))
        return

    mnemonic = word
    if mnemonic not in INSTRUCTIONS:
        raise ValueError(error_unknown_mnemonic(mnemonic))

    operands = []
    for tok in tokens[1:]:
        if tok[0] == 'word':
            operands.append(tok[1])
        elif tok[0] == 'comma':
            continue
        else:
            raise ValueError("Недопустимый токен в операндах: " + str(tok))

    if pass_num == 2:
        instr_info = INSTRUCTIONS[mnemonic]
        itype = instr_info["type"]
        code = encode_instruction(mnemonic, operands, line_num, line_text)
        start_pos = position[current_section]

        if current_section == ".text":
            start_vaddr = vaddr_text + start_pos
            target_addr = ""
            try:
                if itype in ("jmp", "jcc", "short_jmp", "short_jcc"):
                    target = parse_operand(operands[0])
                    target_addr = hex(target)
                elif itype == "reg_imm":
                    op_str = operands[1]
                    if op_str in labels:
                        sec = label_sections[op_str]
                        addr = labels[op_str] + (vaddr_text if sec == ".text" else vaddr_data)
                        target_addr = hex(addr)
                    elif op_str in symbols: # Проверяем символы
                        target_addr = hex(symbols[op_str])
            except Exception:
                target_addr = "ошибка"

            original_cmd = line_text.split(';')[0].strip()
            for i, byte in enumerate(code):
                addr = start_vaddr + i
                byte_hex = "{:02X}".format(byte)
                cmd_to_log = original_cmd if i == 0 else ""
                log_entries.append((hex(addr), byte_hex, target_addr if i == 0 else "", cmd_to_log))

        sections[current_section] += code
        position[current_section] += len(code)
    else:
        instr_info = INSTRUCTIONS[mnemonic]
        itype = instr_info["type"]
        size_map = {
            "reg_imm": 10,
            "cmp_reg_imm": 7,
            "jmp": 5,
            "jcc": 6,
            "none": lambda: len(instr_info["code"]),
            "short_jmp": 2,
            "short_jcc": 2,
            "cmp_reg_reg": 3,
            "test_reg_reg": 3,
            "add_reg_reg": 3,
            "sub_reg_reg": 3,
            "incdec": 3,
        }
        if itype in size_map:
            sz = size_map[itype]
            position[current_section] += sz() if callable(sz) else sz
        else:
            raise ValueError("Неподдерживаемый тип инструкции при подсчёте размера: " + itype)




def parse_tokens(tokens, line_num, line_text):
    if not tokens:
        return
    if len(tokens) >= 2 and tokens[0][0] == 'word' and tokens[1][0] == 'colon':
        label = tokens[0][1]
        labels[label] = position[current_section]
        label_sections[label] = current_section
        rest = tokens[2:]
        if rest:
            parse_instruction_or_directive(rest, line_num, line_text)
        return
    parse_instruction_or_directive(tokens, line_num, line_text)

def parse(source):
    global pass_num, text_size, data_size, comment_size
    global offset_text, offset_data, offset_comment, shstrtab_offset, shdr_offset
    global vaddr_text, vaddr_data
    global sections, position, log_entries

    log_entries = []
    lines = source.split('\n')
    
    # ПРОХОД 1
    pass_num = 1
    position[".text"] = 0
    position[".data"] = 0
    labels.clear()
    label_sections.clear()

    for line_num, line in enumerate(lines, start=1):
        original_line = line.rstrip()
        try:
            tokens = tokenize_line(line)
            parse_tokens(tokens, line_num, original_line)
        except Exception as e:
            error_full = make_error_msg(line_num, original_line, str(e))
            print(error_full, file=sys.stderr)
            sys.exit(1)

    text_size_pass1 = position[".text"]
    data_size_pass1 = position[".data"]
    print("ПРОХОД 1: text_size=" + str(text_size_pass1) + " bytes, data_size=" + str(data_size_pass1) + " bytes")

    # РАЗМЕЩЕНИЕ
    elf_header_size = 64
    ph_size = 56
    ph_num = 3
    ph_table_size = ph_num * ph_size

    offset_text = align_up(elf_header_size + ph_table_size, PAGE_SIZE)
    offset_data = align_up(offset_text + text_size_pass1, PAGE_SIZE)
    vaddr_text = text_vaddr_base
    vaddr_data = align_up(vaddr_text + text_size_pass1, PAGE_SIZE)

    comment_content = "Сборщик КВС".encode('utf-8') + b'\x00'
    comment_size = len(comment_content)
    offset_comment = align_up(offset_data + data_size_pass1, 1)

    shstrtab_content = b"\x00.text\x00.data\x00.comment\x00.shstrtab\x00"
    shstrtab_size = len(shstrtab_content)
    shstrtab_offset = align_up(offset_comment + comment_size, 8)
    shdr_size = 64
    shdr_num = 5
    shdr_offset = align_up(shstrtab_offset + shstrtab_size, 16)

    print("РАЗМЕЩЕНИЕ: .text at offset=" + hex(offset_text) + ", .data at offset=" + hex(offset_data))
    print("ВИРТУАЛЬНЫЕ АДРЕСА: .text at " + hex(vaddr_text) + ", .data at " + hex(vaddr_data))
    print("РАССТОЯНИЕ МЕЖДУ СЕКЦИЯМИ: " + hex(vaddr_data - vaddr_text) + " bytes")

    sections[".comment"] = comment_content

    # ПРОХОД 2
    pass_num = 2
    position[".text"] = 0
    position[".data"] = 0
    sections[".text"] = bytearray()
    sections[".data"] = bytearray()
    
    for line_num, line in enumerate(lines, start=1):
        original_line = line.rstrip()
        try:
            tokens = tokenize_line(line)
            parse_tokens(tokens, line_num, original_line)
        except Exception as e:
            error_full = make_error_msg(line_num, original_line, str(e))
            print(error_full, file=sys.stderr)
            sys.exit(1)

    text_size_pass2 = len(sections[".text"])
    data_size_pass2 = len(sections[".data"])
    print("ПРОХОД 2: text_size=" + str(text_size_pass2) + " bytes, data_size=" + str(data_size_pass2) + " bytes")
    
    if text_size_pass1 != text_size_pass2:
        print("ПРЕДУПРЕЖДЕНИЕ: Размер .text изменился между проходами: " + str(text_size_pass1) + " -> " + str(text_size_pass2))
    if data_size_pass1 != data_size_pass2:
        print("ПРЕДУПРЕЖДЕНИЕ: Размер .data изменился между проходами: " + str(data_size_pass1) + " -> " + str(data_size_pass2))

    text_size = text_size_pass2
    data_size = data_size_pass2

def create_elf(filename):
    global sections, entry_point, labels, vaddr_text, vaddr_data
    global offset_text, offset_data, offset_comment, shstrtab_offset, shdr_offset

    text = sections[".text"]
    data = sections[".data"]
    comment = sections[".comment"]

    actual_text_size = len(text)
    actual_data_size = len(data)
    expected_vaddr_data = align_up(vaddr_text + actual_text_size, PAGE_SIZE)
    if vaddr_data != expected_vaddr_data:
        print("КОРРЕКЦИЯ: vaddr_data исправлен с " + hex(vaddr_data) + " на " + hex(expected_vaddr_data))
        vaddr_data = expected_vaddr_data

    print("ФАКТИЧЕСКИЕ РАЗМЕРЫ: .text=" + str(actual_text_size) + ", .data=" + str(actual_data_size))
    print("КОНЕЧНЫЕ АДРЕСА: .text ends at " + hex(vaddr_text + actual_text_size) + ", .data starts at " + hex(vaddr_data))
    print("ПРОВЕРКА ПЕРЕКРЫТИЯ: " + ("ПЕРЕКРЫТИЕ!" if (vaddr_text + actual_text_size) > vaddr_data else "OK"))

    entry_addr = vaddr_text + labels.get(entry_point, 0)

    shstrtab_content = b"\x00.text\x00.data\x00.comment\x00.shstrtab\x00"
    shstrtab_size = len(shstrtab_content)

    elf_header_size = 64
    ph_size = 56
    ph_num = 3
    shdr_size = 64
    shdr_num = 5

    file_size = shdr_offset + shdr_num * shdr_size
    elf_data = bytearray(file_size)

    # ELF header
    e_ident = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    elf_header = struct.pack(
        '<16sHHIQQQIHHHHHH',
        e_ident,
        2,
        0x3e,
        1,
        entry_addr,
        elf_header_size,
        shdr_offset,
        0,
        elf_header_size,
        ph_size,
        ph_num,
        shdr_size,
        shdr_num,
        4
    )
    elf_data[0:64] = elf_header

    def phdr(p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz):
        return struct.pack('<IIQQQQQQ',
            p_type, p_flags,
            p_offset, p_vaddr, p_vaddr,
            p_filesz, p_memsz,
            PAGE_SIZE
        )

    ph0 = phdr(1, 4, 0, elf_base_vaddr, elf_header_size + ph_num * ph_size, PAGE_SIZE)
    ph1 = phdr(1, 5, offset_text, vaddr_text, len(text), align_up(len(text), PAGE_SIZE))
    ph2 = phdr(1, 6, offset_data, vaddr_data, len(data), align_up(len(data), PAGE_SIZE))

    phdrs = ph0 + ph1 + ph2
    elf_data[elf_header_size : elf_header_size + len(phdrs)] = phdrs

    elf_data[offset_text : offset_text + len(text)] = text
    elf_data[offset_data : offset_data + len(data)] = data
    elf_data[offset_comment : offset_comment + len(comment)] = comment
    elf_data[shstrtab_offset : shstrtab_offset + shstrtab_size] = shstrtab_content

    def shdr(name_idx, sh_type, flags, addr, offset, size, addralign=1):
        return struct.pack('<IIQQQQIIQQ',
            name_idx, sh_type, flags, addr, offset, size,
            0, 0, addralign, 0
        )

    sh0 = shdr(0, 0, 0, 0, 0, 0)
    sh1 = shdr(1, 1, 6, vaddr_text, offset_text, len(text), 16)
    sh2 = shdr(7, 1, 3, vaddr_data, offset_data, len(data), 8)
    sh3 = shdr(13, 1, 0, 0, offset_comment, len(comment), 1)
    sh4 = shdr(22, 3, 0, 0, shstrtab_offset, shstrtab_size, 1)

    shdrs = sh0 + sh1 + sh2 + sh3 + sh4
    elf_data[shdr_offset : shdr_offset + len(shdrs)] = shdrs

    f_out = open(filename, "wb")
    f_out.write(elf_data)
    f_out.close()

    import os
    os.chmod(filename, 0o755)

# === Основной запуск ===
if len(sys.argv) != 2:
    print("Использование: python kvs_5.py <файл.квс>")
    sys.exit(1)

source_file = sys.argv[1]
source_filename = source_file
if not source_file.endswith('.квс'):
    print("Ошибка: файл должен иметь расширение .квс")
    sys.exit(1)

f_in = None
try:
    f_in = open(source_file, "r", encoding="utf-8")
    source = f_in.read()
    f_in.close()
except FileNotFoundError:
    safe_close(f_in)
    print("Ошибка: файл '" + source_file + "' не найден.")
    sys.exit(1)
except UnicodeDecodeError as e:
    safe_close(f_in)
    print("Ошибка кодировки в файле '" + source_file + "': " + str(e))
    sys.exit(1)

try:
    parse(source)
    elf_file = source_file[:-4] + ".elf"
    create_elf(elf_file)
    
    log_file = source_file[:-4] + ".log.csv"
    f_log = open(log_file, "w", encoding="utf-8")
    f_log.write("адрес;байт;целевой_адрес;исходная_команда\n")
    for addr, byte, target, cmd in log_entries:
        if cmd and ('"' in cmd or ';' in cmd):
            cmd = '"' + cmd.replace('"', '""') + '"'
        f_log.write(addr + ";" + byte + ";" + target + ";" + cmd + "\n")
    f_log.close()
    print("Лог создан: " + log_file)
    
    print("ELF-файл создан: " + elf_file)
    print("Запустить: ./" + elf_file)
except SystemExit:
    raise
except Exception as e:
    print("Внутренняя ошибка ассемблера: " + str(e), file=sys.stderr)
    sys.exit(1)