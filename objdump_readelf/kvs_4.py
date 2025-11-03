#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
kvs_4.py
КВС - язык программирования  
без использования re
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
}

REGISTERS = {
    "раикс": 0,   # RAX
    "рдикс": 2,   # RDX  
    "рсиай": 6,   # RSI
    "рдиай": 7,   # RDI
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

# === ELF layout (глобальные переменные для второго прохода и записи) ===
PAGE_SIZE = 0x1000
elf_base_vaddr = 0x400000      # первая страница — заголовки
text_vaddr_base = 0x401000     # вторая страница — .text
data_vaddr_base = 0x402000     # третья страница — .data

# Смещения и адреса (вычисляются после первого прохода)
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
    return {"size": 64, "index": REGISTERS[reg_name]}

# === Функции формирования ошибок ===

def make_error_msg(line_num, line_text, detail):
    return f"Ошибка в файле {source_filename}, строка {line_num}:\n    {line_text}\n{detail}"

def error_invalid_operand_count(mnemonic, expected, got):
    return f"Инструкция '{mnemonic}':\n    ожидается {expected} операнд(а/ов), получено: {got}"

def error_unknown_mnemonic(mnemonic):
    return f"Неизвестная инструкция: '{mnemonic}'"

def error_invalid_register(op_name, reg_name, mnemonic):
    return f"Инструкция '{mnemonic}':\n    операнд '{op_name}' = '{reg_name}' не является допустимым регистром.\n    Допустимые регистры: {', '.join(list(REGISTERS.keys()))}"

def error_invalid_number_format(s):
    return f"Недопустимый формат числа: '{s}'"

def error_unknown_directive(word):
    return f"Неизвестная директива: '{word}'"

def error_missing_label(label):
    return f"Метка не найдена: '{label}'"

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
        if section == ".text":
            # ВО ВТОРОМ ПРОХОДЕ используем вычисленные ранее адреса
            if pass_num == 2:
                return labels[operand] + vaddr_text
            else:
                return labels[operand]  # В первом проходе - только смещение
        elif section == ".data":
            if pass_num == 2:
                return labels[operand] + vaddr_data
            else:
                return labels[operand]
        else:
            raise ValueError(f"Метка в неизвестной секции: {section}")
    if operand in symbols:
        return symbols[operand]
    raise ValueError(f"Неизвестный операнд: {operand}")




def parse_number_token(token):
    if token[0] != 'word':
        raise ValueError(f"Ожидалось число, получено: {token}")
    s = token[1]
    if s.isdigit():
        return int(s)
    if s.startswith("0x"):
        return int(s, 16)
    raise ValueError(error_invalid_number_format(s))

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
        imm = parse_operand(operands[1])

        if 0 <= reg <= 7:
            code.extend(b'\x48')
            code.append(0xB8 + reg)
            code.extend(struct.pack('<Q', imm))
        elif 8 <= reg <= 15:
            code.extend(b'\x49')
            code.append(0xB8 + (reg - 8))
            code.extend(struct.pack('<Q', imm))
        else:
            raise ValueError(f"Недопустимый регистр в '{mnemonic}'")

    elif itype == "cmp_reg_imm":
        if len(operands) != 2:
            raise ValueError(error_invalid_operand_count(mnemonic, 2, len(operands)))
        reg_info = get_reg_info(operands[0])
        if reg_info is None:
            raise ValueError(error_invalid_register("регистра", operands[0], mnemonic))
        reg = reg_info["index"]
        imm = parse_operand(operands[1])

        if -0x80000000 <= imm <= 0x7FFFFFFF:
            rex = 0x48
            if reg >= 8:
                rex |= 0x01
            code.append(rex)
            code.append(0x81)
            modrm = 0xF8 | (reg & 7)
            code.append(modrm)
            code.extend(struct.pack('<i', imm))
        else:
            raise ValueError(f"Непосредственное значение слишком велико для сравнения: {imm}")

    elif itype == "jmp":
        if len(operands) != 1:
            raise ValueError(error_invalid_operand_count(mnemonic, 1, len(operands)))
        code.extend(instr["code"])
        target = parse_operand(operands[0])
        current_addr = vaddr_text + position[".text"]
        offset = target - (current_addr + 5)
        if offset < -0x80000000 or offset > 0x7FFFFFFF:
            raise ValueError(f"Цель слишком далеко для 32-битного смещения в инструкции '{mnemonic}': {offset} (должно быть в [-2^31, 2^31-1])")
        code.extend(struct.pack('<i', offset))

    elif itype == "jcc":
        if len(operands) != 1:
            raise ValueError(error_invalid_operand_count(mnemonic, 1, len(operands)))
        code.extend(instr["code"])
        target = parse_operand(operands[0])
        current_addr = vaddr_text + position[".text"]
        offset = target - (current_addr + 6)
        if offset < -0x80000000 or offset > 0x7FFFFFFF:
            raise ValueError(f"Цель условного перехода слишком далеко: {offset}")
        code.extend(struct.pack('<i', offset))

    else:
        raise ValueError(f"Неизвестный тип инструкции: {itype}")

    return bytes(code)

def parse_instruction_or_directive(tokens, line_num, line_text):
    global current_section, entry_point
    first = tokens[0]
    if first[0] != 'word':
        raise ValueError(f"Ожидалось слово, получено: {first}")
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
                raise ValueError(f"{word} требует строку в кавычках")
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
            raise ValueError(f"Недопустимый токен в операндах: {tok}")

    if pass_num == 2:
        # === НАЧАЛО ИЗМЕНЕНИЙ ДЛЯ УЛУЧШЕННОГО ЛОГИРОВАНИЯ ===
        instr_info = INSTRUCTIONS[mnemonic]
        itype = instr_info["type"]
        code = encode_instruction(mnemonic, operands, line_num, line_text)
        start_pos = position[current_section]

        if current_section == ".text":
            start_vaddr = vaddr_text + start_pos
            target_addr = ""  # теперь называется "целевой_адрес"
            try:
                if itype in ("jmp", "jcc"):
                    # Цель перехода
                    target = parse_operand(operands[0])
                    target_addr = hex(target)
                elif itype == "reg_imm":
                    # Проверяем, является ли второй операнд меткой
                    op_str = operands[1]
                    if op_str in labels:
                        sec = label_sections[op_str]
                        if sec == ".text":
                            addr = labels[op_str] + vaddr_text
                        elif sec == ".data":
                            addr = labels[op_str] + vaddr_data
                        else:
                            addr = labels[op_str]
                        target_addr = hex(addr)
                    # Иначе — число, оставляем пустым
            except Exception:
                target_addr = "ошибка"

            original_cmd = line_text.split(';')[0].strip()
            for i, byte in enumerate(code):
                addr = start_vaddr + i
                byte_hex = f"{byte:02X}"
                cmd_to_log = original_cmd if i == 0 else ""
                log_entries.append((hex(addr), byte_hex, target_addr if i == 0 else "", cmd_to_log))

        sections[current_section] += code
        position[current_section] += len(code)
        # === КОНЕЦ ИЗМЕНЕНИЙ ===
    else:
        instr_info = INSTRUCTIONS[mnemonic]
        itype = instr_info["type"]
        size_map = {
            "reg_imm": 10,
            "cmp_reg_imm": 7,
            "jmp": 5,
            "jcc": 6,
            "none": lambda: len(instr_info["code"]),
        }
        if itype in size_map:
            sz = size_map[itype]
            position[current_section] += sz() if callable(sz) else sz
        else:
            raise ValueError(f"Неподдерживаемый тип инструкции при подсчёте размера: {itype}")

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

    # Очистка лога перед новой сборкой
    log_entries = []

    lines = source.split('\n')
    
    # === ПРОХОД 1: анализ (только подсчет размеров) ===
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

    # СОХРАНИТЬ размеры из первого прохода
    text_size_pass1 = position[".text"]
    data_size_pass1 = position[".data"]
    
    print(f"ПРОХОД 1: text_size={text_size_pass1} bytes, data_size={data_size_pass1} bytes")

    # === ВЫЧИСЛЕНИЕ РАЗМЕЩЕНИЯ с фиксированными размерами ===
    elf_header_size = 64
    ph_size = 56
    ph_num = 3
    ph_table_size = ph_num * ph_size

    # Вычисляем смещения с использованием размеров из первого прохода
    offset_text = align_up(elf_header_size + ph_table_size, PAGE_SIZE)
    offset_data = align_up(offset_text + text_size_pass1, PAGE_SIZE)
    
    # ВИРТУАЛЬНЫЕ АДРЕСА - ИСПРАВЛЕНИЕ!
    vaddr_text = text_vaddr_base  # 0x401000
    vaddr_data = align_up(vaddr_text + text_size_pass1, PAGE_SIZE)  # Ключевое исправление!

    # <<< ИЗМЕНЕНИЕ: новое содержимое .comment >>>
    comment_content = "Сборщик КВС".encode('utf-8') + b'\x00'
    comment_size = len(comment_content)
    offset_comment = align_up(offset_data + data_size_pass1, 1)

    # Обновлённый .shstrtab с .comment
    shstrtab_content = b"\x00.text\x00.data\x00.comment\x00.shstrtab\x00"
    shstrtab_size = len(shstrtab_content)
    shstrtab_offset = align_up(offset_comment + comment_size, 8)
    shdr_size = 64
    shdr_num = 5
    shdr_offset = align_up(shstrtab_offset + shstrtab_size, 16)

    print(f"РАЗМЕЩЕНИЕ: .text at offset={hex(offset_text)}, .data at offset={hex(offset_data)}")
    print(f"ВИРТУАЛЬНЫЕ АДРЕСА: .text at {hex(vaddr_text)}, .data at {hex(vaddr_data)}")
    print(f"РАССТОЯНИЕ МЕЖДУ СЕКЦИЯМИ: {hex(vaddr_data - vaddr_text)} bytes")
    print(f"РАЗМЕР .text: {text_size_pass1} bytes, требуется выравнивание до: {hex(align_up(text_size_pass1, PAGE_SIZE))}")

    # Сохраняем .comment для второго прохода
    sections[".comment"] = comment_content

    # === ПРОХОД 2: генерация (с фиксированными размерами) ===
    pass_num = 2
    position[".text"] = 0
    position[".data"] = 0
    sections[".text"] = bytearray()
    sections[".data"] = bytearray()
    
    # ВТОРОЙ ПРОХОД: используем сохраненные размеры для вычисления адресов
    for line_num, line in enumerate(lines, start=1):
        original_line = line.rstrip()
        try:
            tokens = tokenize_line(line)
            parse_tokens(tokens, line_num, original_line)
        except Exception as e:
            error_full = make_error_msg(line_num, original_line, str(e))
            print(error_full, file=sys.stderr)
            sys.exit(1)

    # ПРОВЕРКА: размеры во втором проходе должны совпадать с первым
    text_size_pass2 = len(sections[".text"])
    data_size_pass2 = len(sections[".data"])
    
    print(f"ПРОХОД 2: text_size={text_size_pass2} bytes, data_size={data_size_pass2} bytes")
    
    if text_size_pass1 != text_size_pass2:
        print(f"ПРЕДУПРЕЖДЕНИЕ: Размер .text изменился между проходами: {text_size_pass1} -> {text_size_pass2}")
    if data_size_pass1 != data_size_pass2:
        print(f"ПРЕДУПРЕЖДЕНИЕ: Размер .data изменился между проходами: {data_size_pass1} -> {data_size_pass2}")

    # Используем фактические размеры для финальных вычислений
    text_size = text_size_pass2
    data_size = data_size_pass2

def create_elf(filename):
    global sections, entry_point, labels, vaddr_text, vaddr_data
    global offset_text, offset_data, offset_comment, shstrtab_offset, shdr_offset

    text = sections[".text"]
    data = sections[".data"]
    comment = sections[".comment"]

    # ПЕРЕПРОВЕРКА и коррекция адресов
    actual_text_size = len(text)
    actual_data_size = len(data)
    
    # Убедись, что vaddr_data вычислен правильно
    expected_vaddr_data = align_up(vaddr_text + actual_text_size, PAGE_SIZE)
    if vaddr_data != expected_vaddr_data :
        print(f"КОРРЕКЦИЯ: vaddr_data исправлен с {hex(vaddr_data)} на {hex(expected_vaddr_data)}")
        vaddr_data = expected_vaddr_data

    print(f"ФАКТИЧЕСКИЕ РАЗМЕРЫ: .text={actual_text_size}, .data={actual_data_size}")
    print(f"КОНЕЧНЫЕ АДРЕСА: .text ends at {hex(vaddr_text + actual_text_size)}, .data starts at {hex(vaddr_data)}")
    print(f"ПРОВЕРКА ПЕРЕКРЫТИЯ: {'ПЕРЕКРЫТИЕ!' if (vaddr_text + actual_text_size) > vaddr_data else 'OK'}")

    # Точка входа
    entry_addr = vaddr_text + labels.get(entry_point, 0)

    # .shstrtab
    shstrtab_content = b"\x00.text\x00.data\x00.comment\x00.shstrtab\x00"
    shstrtab_size = len(shstrtab_content)

    # Размеры
    elf_header_size = 64
    ph_size = 56
    ph_num = 3
    shdr_size = 64
    shdr_num = 5

    file_size = shdr_offset + shdr_num * shdr_size
    elf_data = bytearray(file_size)

    # === 1. ELF-заголовок ===
    e_ident = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    elf_header = struct.pack(
        '<16sHHIQQQIHHHHHH',
        e_ident,
        2,              # ET_EXEC
        0x3e,           # EM_X86_64
        1,              # version
        entry_addr,     # entry
        elf_header_size,# phoff
        shdr_offset,    # shoff
        0,              # flags
        elf_header_size,
        ph_size,
        ph_num,
        shdr_size,
        shdr_num,
        4               # .shstrtab index
    )
    elf_data[0:64] = elf_header

    # === 2. Program Headers ===
    def phdr(p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz):
        return struct.pack('<IIQQQQQQ',
            p_type, p_flags,
            p_offset, p_vaddr, p_vaddr,
            p_filesz, p_memsz,
            PAGE_SIZE
        )

    ph0 = phdr(
        p_type=1,
        p_flags=4,
        p_offset=0,
        p_vaddr=elf_base_vaddr,
        p_filesz=elf_header_size + ph_num * ph_size,
        p_memsz=PAGE_SIZE
    )

    ph1 = phdr(
        p_type=1,
        p_flags=5,
        p_offset=offset_text,
        p_vaddr=vaddr_text,
        p_filesz=len(text),
        p_memsz=align_up(len(text), PAGE_SIZE)  # Выровненный размер в памяти
    )

    ph2 = phdr(
        p_type=1,
        p_flags=6,
        p_offset=offset_data,
        p_vaddr=vaddr_data,
        p_filesz=len(data),
        p_memsz=align_up(len(data), PAGE_SIZE)  # Выровненный размер в памяти
    )

    phdrs = ph0 + ph1 + ph2
    elf_data[elf_header_size : elf_header_size + len(phdrs)] = phdrs

    # === 3. Секции ===
    elf_data[offset_text : offset_text + len(text)] = text
    elf_data[offset_data : offset_data + len(data)] = data
    elf_data[offset_comment : offset_comment + len(comment)] = comment
    elf_data[shstrtab_offset : shstrtab_offset + shstrtab_size] = shstrtab_content

    # === 4. Section Headers ===
    def shdr(name_idx, sh_type, flags, addr, offset, size, addralign=1):
        return struct.pack('<IIQQQQIIQQ',
            name_idx, sh_type, flags, addr, offset, size,
            0, 0, addralign, 0
        )

    # Индексы: ""=0, ".text"=1, ".data"=7, ".comment"=13, ".shstrtab"=22
    sh0 = shdr(0, 0, 0, 0, 0, 0)
    sh1 = shdr(1, 1, 6, vaddr_text, offset_text, len(text), 16)
    sh2 = shdr(7, 1, 3, vaddr_data, offset_data, len(data), 8)
    sh3 = shdr(13, 1, 0, 0, offset_comment, len(comment), 1)
    sh4 = shdr(22, 3, 0, 0, shstrtab_offset, shstrtab_size, 1)

    shdrs = sh0 + sh1 + sh2 + sh3 + sh4
    elf_data[shdr_offset : shdr_offset + len(shdrs)] = shdrs

    # === Запись ===
    with open(filename, "wb") as f:
        f.write(elf_data)

    import os
    os.chmod(filename, 0o755)

    
# === Основной запуск ===

if len(sys.argv) != 2:
    print("Использование: python kvs_.py <файл.квс>")
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
    print(f"Ошибка: файл '{source_file}' не найден.")
    sys.exit(1)
except UnicodeDecodeError as e:
    safe_close(f_in)
    print(f"Ошибка кодировки в файле '{source_file}': {e}")
    sys.exit(1)

try:
    parse(source)
    elf_file = source_file[:-4] + ".elf"
    create_elf(elf_file)
    
    # === ЗАПИСЬ CSV-ЛОГА С НОВЫМ ИМЕНЕМ СТОЛБЦА ===
    log_file = source_file[:-4] + ".log.csv"
    with open(log_file, "w", encoding="utf-8") as f_log:
        f_log.write("адрес;байт;целевой_адрес;исходная_команда\n")  # ← изменено имя столбца
        for addr, byte, target, cmd in log_entries:
            if cmd and ('"' in cmd or ';' in cmd):
                cmd = '"' + cmd.replace('"', '""') + '"'
            f_log.write(f"{addr};{byte};{target};{cmd}\n")
    print(f"Лог создан: {log_file}")
    
    print(f"ELF-файл создан: {elf_file}")
    print("Запустить: ./" + elf_file)
    print(f"Проверить: objdump -D {elf_file}")
    print(f"Проверить: eu-readelf -a {elf_file}")
    print(f"Проверить: readelf -l {elf_file}")
    print(f"Проверить: file {elf_file}")
except SystemExit:
    raise
except Exception as e:
    print(f"Внутренняя ошибка ассемблера: {e}", file=sys.stderr)
    sys.exit(1)