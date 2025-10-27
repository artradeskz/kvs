"""САМАЯ КОРРЕКТНАЯ ВЕРСИЯ С ПОДРОБНЫМИ ОШИБКАМИ
 ~70% корректной машинной кодогенерации
 по возможности: автоматизировать тестирование кодогенерации
"""

# === СТИЛЬ КОДА И ОГРАНИЧЕНИЯ ДЛЯ САМОКОМПИЛЯЦИИ ===
#
# Этот код написан с учётом будущей возможности самокомпиляции
# (например, трансляции на C или на собственный ассемблер).
# Поэтому соблюдаются следующие правила:
#
# 1. НЕ ИСПОЛЬЗУЮТСЯ f-строки.
#    → Вместо них — конкатенация строк и str()/hex()/int().
#
# 2. НЕ ИСПОЛЬЗУЕТСЯ оператор `with` для работы с файлами.
#    → Вместо него — явные open() и close().
#
# 3. НЕ ИСПОЛЬЗУЕТСЯ ООП (классы, методы, self и т.п.).
#    → Весь код — глобальные функции и переменные.
#
# 4. ИЗБЕГАЕТСЯ сложный Python-специфичный синтаксис:
#    - нет list/dict comprehensions,
#    - нет лямбд,
#    - нет eval/exec (кроме временного парсинга, если необходимо),
#    - нет распаковки (*args, **kwargs),
#    - нет декораторов.
#
# 5. ДУБЛИРОВАНИЕ КОДА ДОПУСТИМО, если оно:
#    - упрощает чтение,
#    - изолирует логику,
#    - облегчает будущую ручную перезапись или трансляцию.
#
# 6. Все структуры данных — простые (dict, list, bytearray).
#    → Нет namedtuple, dataclass, enum и т.п.
#
# 7. Используются только базовые конструкции:
#    if/elif/else, while, for, функции, глобальные переменные.
#
# === РАСШИРЕНИЕ: ПРЯМАЯ ВСТАВКА ОПКОДОВ ===
#
# Для гибкости и поддержки экспериментальных или ещё не описанных
# инструкций добавлена директива:
#
#     .байт 0xXX 0xYY ...
#
# Она позволяет вставлять произвольные байты машинного кода
# непосредственно в секцию (.text или .data).
#
# ВАЖНО:
# - Цифровые опкоды — НЕ замена мнемоникам.
# - Русские мнемоники будут постепенно расширяться и покрывать
#   всё больше инструкций x86-64.
# - .байт используется ТОЛЬКО как временный или специализированный
#   механизм для случаев, когда мнемоника ещё не реализована,
#   недокументирована или требует точного контроля, если мнемоника 
#   описана - .байт не использовать.
# - Данные (.строка, .константа) остаются в человекочитаемом виде.
#
# Цель: сделать код максимально "механически переносимым"
# в другой язык или в собственный ассемблер без потери логики,
# при этом сохраняя возможность полного контроля над генерируемым
# машинным кодом.
#
# ===================================================


import sys

# Глобальная переменная для имени исходного файла (для сообщений об ошибках)
source_filename = ""

def pack_u16_le(val):
    return bytes([
        (val >> 0) & 0xFF,
        (val >> 8) & 0xFF
    ])

def pack_u32_le(val):
    return bytes([
        (val >> 0) & 0xFF,
        (val >> 8) & 0xFF,
        (val >> 16) & 0xFF,
        (val >> 24) & 0xFF
    ])

def pack_u64_le(val):
    return bytes([
        (val >> 0) & 0xFF,
        (val >> 8) & 0xFF,
        (val >> 16) & 0xFF,
        (val >> 24) & 0xFF,
        (val >> 32) & 0xFF,
        (val >> 40) & 0xFF,
        (val >> 48) & 0xFF,
        (val >> 56) & 0xFF
    ])

def pack_i32_le(val):
    if val < 0:
        val = (1 << 32) + val
    return pack_u32_le(val)

def safe_close(f):
    if f is not None:
        f.close()

# === Глобальные данные ===
INSTRUCTIONS = {
    # Базовые
    "переместить": {"code": b"\x48\x89", "type": "reg_reg"},        # mov
    "переместить_имм": {"code": None, "type": "reg_imm"},           # mov
    "прибавить": {"code": b"\x48\x01", "type": "reg_reg"},          # add
    "вычесть": {"code": b"\x48\x29", "type": "reg_reg"},            # sub
    "вызвать": {"code": b"\xE8", "type": "call"},                   # call
    "вернуться": {"code": b"\xC3", "type": "none"},                 # ret
    "вызов_системы": {"code": b"\x0F\x05", "type": "none"},         # syscall
    "сравнить": {"code": b"\x48\x39", "type": "reg_reg"},           # cmp
    "переход": {"code": b"\xE9", "type": "jmp"},                    # jmp
    "переход_если_равно": {"code": b"\x0F\x84", "type": "jcc"},     # je / jz
    "переход_если_неравно": {"code": b"\x0F\x85", "type": "jcc"},   # jne / jnz
    "втолкнуть": {"code": b"\x50", "type": "push"},                 # push
    "вытолкнуть": {"code": b"\x58", "type": "pop"},                 # pop
    "нет_операции": {"code": b"\x90", "type": "none"},              # nop
    "остановить": {"code": b"\xF4", "type": "none"},                # hlt

    # Арифметика
    "увеличить": {"code": b"\xFF", "subop": 0, "type": "incdec"},           # inc
    "уменьшить": {"code": b"\xFF", "subop": 1, "type": "incdec"},           # dec
    "отрицать": {"code": b"\xF7", "subop": 3, "type": "unary"},             # neg
    "умножить": {"code": b"\xF7", "subop": 4, "type": "muldiv"},            # mul
    "умножить_знаковое": {"code": b"\xF7", "subop": 5, "type": "muldiv"},   # imul
    "разделить": {"code": b"\xF7", "subop": 6, "type": "muldiv"},           # div
    "разделить_знаковое": {"code": b"\xF7", "subop": 7, "type": "muldiv"},  # idiv

    # Логика
    "и": {"code": b"\x48\x21", "type": "reg_reg"},                      # and
    "или": {"code": b"\x48\x09", "type": "reg_reg"},                    # or
    "исключающее_или": {"code": b"\x48\x31", "type": "reg_reg"},        # xor
    "инвертировать": {"code": b"\xF7", "subop": 2, "type": "unary"},    # not
    "проверить": {"code": b"\x48\x85", "type": "test"},                 # test

    # Адресация
    "загрузить_адрес": {"code": b"\x48\x8D", "type": "lea"},  # lea

    # Сдвиги и вращения
    "сдвиг_влево": {"code": b"\x48\xC1\xE0", "type": "shift_imm"},                  # shl
    "сдвиг_вправо": {"code": b"\x48\xC1\xE8", "type": "shift_imm"},                 # shr
    "сдвиг_арифметический_влево": {"code": b"\x48\xC1\xE0", "type": "shift_imm"},   # sal (same as shl)
    "сдвиг_арифметический_вправо": {"code": b"\x48\xC1\xF8", "type": "shift_imm"},  # sar
    "вращать_влево": {"code": b"\x48\xC1\xC0", "type": "rotate_imm"},               # rol
    "вращать_вправо": {"code": b"\x48\xC1\xC8", "type": "rotate_imm"},              # ror

    # Флаги
    "установить_перенос": {"code": b"\xF9", "type": "none"},        # stc
    "сбросить_перенос": {"code": b"\xF8", "type": "none"},          # clc
    "установить_направление": {"code": b"\xFD", "type": "none"},    # std
    "сбросить_направление": {"code": b"\xFC", "type": "none"},      # cld

    # Прерывания
    "прервать": {"code": b"\xCD", "type": "int"},  # int

    # Расширение регистра
    "переместить_с_нулями": {"code": b"\x48\x0F\xB6", "type": "movzx"},     # movzx
    "переместить_со_знаком": {"code": b"\x48\x0F\xBE", "type": "movsx"},    # movsx

    # Обмен
    "обменять": {"code": b"\x48\x87", "type": "xchg"},  # xchg

    # Флаги (полные)
    "втолкнуть_флаги": {"code": b"\x9C", "type": "none"},   # pushf
    "вытолкнуть_флаги": {"code": b"\x9D", "type": "none"},  # popf

    # Условные переходы по CF
    "переход_если_перенос": {"code": b"\x0F\x82", "type": "jcc"},       # jc
    "переход_если_нет_переноса": {"code": b"\x0F\x83", "type": "jcc"},  # jnc

    # Цикл
    "цикл": {"code": b"\xE2", "type": "loop"},  # loop

    # Альтернативный системный вызов
    "войти_в_систему": {"code": b"\x0F\x34", "type": "none"},  # sysenter

    # Строковые операции
    "переместить_байт": {"code": b"\xA4", "type": "none"},      # movsb
    "переместить_слово": {"code": b"\xA5", "type": "none"},     # movsw / movsd / movsq (depends on prefix)
    "сравнить_байты": {"code": b"\xA6", "type": "none"},        # cmpsb
    "сканировать_байт": {"code": b"\xAE", "type": "none"},      # scasb

    # Специальные команды
    "идентифицировать_процессор": {"code": b"\x0F\xA2", "type": "none"},    # cpuid
    "прочитать_счетчик": {"code": b"\x0F\x31", "type": "none"},             # rdtsc
    "получить_управление": {"code": b"\x0F\x01\xD0", "type": "none"},       # vmcall (or other, context-dependent)

    # восьмибитные
    "загрузить_байт": {"code": None, "type": "mov_reg8_imm8"},      # mov
    "прибавить_байт": {"code": b"\x00", "type": "add_reg8_reg8"},   # add
    "сохранить_байт": {"code": b"\x88", "type": "mov_mem8_reg8"},   # mov

    # Условные переходы по знаку (SF = OF)
    "переход_если_больше_или_равно": {"code": b"\x0F\x8D", "type": "jcc"},  # jge

    "сохранить_в_адрес": {"code": b"\x88", "type": "store_reg8_to_reg64"},  # mov

    # Сравнение с непосредственным значением
    "сравнить_с": {"code": None, "type": "cmp_reg_imm"},  # cmp

    # Условные переходы по нулю/не нулю (альтернативные названия)
    "переход_если_ноль": {"code": b"\x0F\x84", "type": "jcc"},      # jz
    "переход_если_не_ноль": {"code": b"\x0F\x85", "type": "jcc"},   # jnz

    # Условные переходы по знаку
    "переход_если_меньше": {"code": b"\x0F\x8C", "type": "jcc"},            # jl
    "переход_если_больше": {"code": b"\x0F\x8F", "type": "jcc"},            # jg
    "переход_если_меньше_или_равно": {"code": b"\x0F\x8E", "type": "jcc"},  # jle
    "переход_если_больше_или_равно": {"code": b"\x0F\x8D", "type": "jcc"},  # jge

    # Безусловный короткий переход (опционально)
    "короткий_переход": {"code": b"\xEB", "type": "short_jmp"},  # jmp (short)

    # Чтение из памяти в регистр (64-бит)
    "загрузить": {"code": b"\x48\x8B", "type": "mov_reg_mem"},  # mov

    # Сохранение регистра в память (64-бит)
    "сохранить": {"code": b"\x48\x89", "type": "mov_mem_reg"},  # mov

    # 32-битные операции (часто нужны для совместимости и оптимизации)
    "переместить32": {"code": b"\x89", "type": "mov32_reg_reg"},    # mov
    "прибавить32": {"code": b"\x01", "type": "add32_reg_reg"},      # add
    "вычесть32": {"code": b"\x29", "type": "sub32_reg_reg"},        # sub
    "сравнить32": {"code": b"\x39", "type": "cmp32_reg_reg"},       # cmp

    # 8-битные операции (расширение)
    "вычесть_байт": {"code": b"\x28", "type": "sub_reg8_reg8"},     # sub
    "сравнить_байт": {"code": b"\x38", "type": "cmp_reg8_reg8"},    # cmp

    # Арифметика с непосредственным значением (64-бит, но через add/sub imm32 sign-extended)
    "прибавить_непосредственно": {"code": None, "type": "add_reg_imm"},     # add
    "вычесть_непосредственно": {"code": None, "type": "sub_reg_imm"},       # sub

    # Обмен с памятью
    "обменять_с_памятью": {"code": b"\x48\x87", "type": "xchg_mem_reg"},  # xchg

    # Очистка регистра (xor reg, reg — идиома)
    "очистить": {"code": b"\x48\x31", "type": "xor_self"},  # xor

    # Стековые операции с памятью
    "втолкнуть_из_памяти": {"code": b"\xFF", "subop": 6, "type": "push_mem"},   # push
    "вытолкнуть_в_память": {"code": b"\x8F", "subop": 0, "type": "pop_mem"},    # pop

    # Отладка
    "отладка": {"code": b"\xCC", "type": "none"},  # int3

    # Ввод-вывод (для простых демонстраций)
    "ввод_байта": {"code": b"\xE4", "type": "in_imm"},      # in
    "вывод_байта": {"code": b"\xE6", "type": "out_imm"},    # out
}



REGISTERS = {
    # 64-битные регистры
    "раикс": 0,   # RAX
    "рсикс": 1,   # RCX
    "рдикс": 2,   # RDX
    "рбикс": 3,   # RBX
    "рсипи": 4,   # RSP
    "рбипи": 5,   # RBP
    "рсиай": 6,   # RSI
    "рдиай": 7,   # RDI
    "р8": 8,      # R8
    "р9": 9,      # R9
    "р10": 10,    # R10
    "р11": 11,    # R11
    "р12": 12,    # R12
    "р13": 13,    # R13
    "р14": 14,    # R14
    "р15": 15,    # R15

    # 32-битные регистры
    "еаикс": 0,   # EAX
    "есикс": 1,   # ECX
    "едикс": 2,   # EDX
    "ебикс": 3,   # EBX
    "есипи": 4,   # ESP
    "ебипи": 5,   # EBP
    "есиай": 6,   # ESI
    "едиай": 7,   # EDI
    "р8д": 8,     # R8D
    "р9д": 9,     # R9D
    "р10д": 10,   # R10D
    "р11д": 11,   # R11D
    "р12д": 12,   # R12D
    "р13д": 13,   # R13D
    "р14д": 14,   # R14D
    "р15д": 15,   # R15D

    # 16-битные регистры
    "аикс": 0,    # AX
    "сикс": 1,    # CX
    "дикс": 2,    # DX
    "бикс": 3,    # BX
    "эсп": 4,     # SP (Stack Pointer)
    "бипи": 5,    # BP (Base Pointer)
    "эс": 6,      # SI (Source Index)
    "ди": 7,      # DI (Destination Index)
    "р8в": 8,     # R8W
    "р9в": 9,     # R9W
    "р10в": 10,   # R10W
    "р11в": 11,   # R11W
    "р12в": 12,   # R12W
    "р13в": 13,   # R13W
    "р14в": 14,   # R14W
    "р15в": 15,   # R15W

    # 8-битные регистры (младшие байты)
    "ал": 0,      # AL
    "кл": 1,      # CL
    "дл": 2,      # DL
    "бл": 3,      # BL
    "спл": 4,     # SPL
    "бпл": 5,     # BPL
    "сил": 6,     # SIL
    "дил": 7,     # DIL
    "р8б": 8,     # R8B
    "р9б": 9,     # R9B
    "р10б": 10,   # R10B
    "р11б": 11,   # R11B
    "р12б": 12,   # R12B
    "р13б": 13,   # R13B
    "р14б": 14,   # R14B
    "р15б": 15,   # R15B

    # 8-битные регистры (старшие байты - только для первых 4 регистров)
    "аш": 0,      # AH
    "чш": 1,      # CH
    "дш": 2,      # DH
    "бш": 3,      # BH
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
code_start = 0x400000

# ELF layout
text_size = 0
data_size = 0
vaddr_text = 0
vaddr_data = 0
offset_text = 0
offset_data = 0
memsz_text = 0
memsz_data = 0

# Логи
log_file = None
tokens_log = None

# === Вспомогательные функции ===

def log(message):
    log_file.write(message + "\n")
    log_file.flush()

def log_tokens(line_num, tokens):
    tokens_log.write("Line " + str(line_num) + ": " + str(tokens) + "\n")
    tokens_log.flush()

def close_log():
    safe_close(log_file)
    safe_close(tokens_log)

def log_labels():
    log("=== Метки и их адреса ===")
    for label, pos in labels.items():
        section = label_sections.get(label, "неизвестно")
        base_addr = vaddr_text if section == ".text" else vaddr_data
        abs_addr = base_addr + pos
        value = symbols.get(label, "N/A")
        log("Метка '" + label + "': секция = " + section +
            ", позиция = " + str(pos) +
            ", абсолютный адрес = " + hex(abs_addr) +
            ", значение = " + str(value))

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
    return (
        "Ошибка в файле " + source_filename + ", строка " + str(line_num) + ":\n" +
        "    " + line_text + "\n" +
        detail
    )

def error_invalid_operand_count(mnemonic, expected, got):
    return (
        "Инструкция '" + mnemonic + "':\n" +
        "    ожидается " + str(expected) + " операнд(а/ов), получено: " + str(got)
    )

def error_unknown_mnemonic(mnemonic):
    return "Неизвестная инструкция: '" + mnemonic + "'"

def error_invalid_register(op_name, reg_name, mnemonic):
    return (
        "Инструкция '" + mnemonic + "':\n" +
        "    операнд '" + op_name + "' = '" + reg_name + "' не является допустимым регистром.\n" +
        "    Допустимые регистры: " + ", ".join(list(REGISTERS.keys()))
    )

def error_expected_register(op_name, value, mnemonic):
    return (
        "Инструкция '" + mnemonic + "':\n" +
        "    операнд '" + op_name + "' = '" + value + "' должен быть регистром, но это число или метка."
    )

def error_invalid_number_format(s):
    return "Недопустимый формат числа: '" + s + "'"

def error_byte_out_of_range(val_str, val):
    return "Байт должен быть в диапазоне 0–255: '" + val_str + "' = " + str(val)

def error_unknown_directive(word):
    return "Неизвестная директива: '" + word + "'"

def error_missing_label(label):
    return "Метка не найдена: '" + label + "'"

def error_unexpected_token_in_operands(tok):
    return "Недопустимый токен в операндах: " + str(tok)

def error_unexpected_string_in_byte():
    return ".байт требует числовые значения, не строки"

def error_unterminated_string():
    return "Незакрытая кавычка в строке"

def error_invalid_address_operand(addr_op):
    return "Первый операнд должен быть [регистр], получено: " + addr_op

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
        base_addr = vaddr_text if section == ".text" else vaddr_data
        return labels[operand] + base_addr
    if operand in symbols:
        return symbols[operand]
    raise ValueError("Неизвестный операнд: " + operand)

def parse_number_token(token):
    if token[0] != 'word':
        raise ValueError("Ожидалось число, получено: " + str(token))
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

    elif itype == "reg_reg":
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
        dst_size = dst_info["size"]
        src_size = src_info["size"]

        if dst_size != src_size:
            raise ValueError("Размеры операндов не совпадают в инструкции '" + mnemonic + "'")

        # Определяем, нужен ли REX.W
        use_rex_w = (dst_size == 64)
        use_66_prefix = (dst_size == 16)

        rex = 0x40
        if use_rex_w:
            rex |= 0x08
        if src >= 8:
            rex |= 0x04
        if dst >= 8:
            rex |= 0x01

        # Старшие байты запрещают REX
        if dst_info.get("high8") or src_info.get("high8"):
            if rex != 0x40:
                raise ValueError("Нельзя использовать старшие байты (аш/чш/дш/бш) с расширенными регистрами (р8–р15)")
            rex = 0

        op_base = instr["code"]
        if op_base[0] == 0x48 and len(op_base) == 2:
            # Это 64-битная инструкция по умолчанию, но мы пересчитываем
            actual_op = op_base[1]
        else:
            actual_op = op_base[0]

        if use_66_prefix:
            code.append(0x66)
        if rex != 0x40 or use_rex_w:
            code.append(rex)
        code.append(actual_op)
        modrm = 0xC0 | ((src & 7) << 3) | (dst & 7)
        code.append(modrm)

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
                code.extend(pack_u64_le(imm))
            elif 8 <= reg <= 15:
                code.extend(b'\x49')
                code.append(0xB8 + (reg - 8))
                code.extend(pack_u64_le(imm))
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
                code.extend(pack_u32_le(imm & 0xFFFFFFFF))
            else:
                raise ValueError("32-битное непосредственное значение вне диапазона: " + str(imm))
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
                raise ValueError("16-битное непосредственное значение вне диапазона: " + str(imm))
        elif size == 8:
            if not (0 <= imm <= 255):
                raise ValueError("8-битное значение вне диапазона 0–255: " + str(imm))
            if reg_info.get("high8"):
                if reg < 4:
                    code.append(0xB0 + reg + 4)  # AH=4, CH=5, DH=6, BH=7 → B4..B7
                    code.append(imm & 0xFF)
                else:
                    raise ValueError("Старшие байты доступны только для первых 4 регистров")
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
            raise ValueError("Неподдерживаемый размер регистра в '" + mnemonic + "'")

    elif itype == "call" or itype == "jmp":
        if len(operands) != 1:
            raise ValueError(error_invalid_operand_count(mnemonic, 1, len(operands)))
        code.extend(instr["code"])
        target = parse_operand(operands[0])
        current_addr = vaddr_text + position[".text"]
        offset = target - (current_addr + 5)
        if offset < -0x80000000 or offset > 0x7FFFFFFF:
            raise ValueError(
                "Цель слишком далеко для 32-битного смещения в инструкции '" + mnemonic + "': " +
                str(offset) + " (должно быть в [-2^31, 2^31-1])"
            )
        code.extend(pack_i32_le(offset))

    elif itype == "jcc":
        if len(operands) != 1:
            raise ValueError(error_invalid_operand_count(mnemonic, 1, len(operands)))
        code.extend(instr["code"])
        target = parse_operand(operands[0])
        current_addr = vaddr_text + position[".text"]
        offset = target - (current_addr + 6)
        if offset < -0x80000000 or offset > 0x7FFFFFFF:
            raise ValueError("Цель условного перехода слишком далеко: " + str(offset))
        code.extend(pack_i32_le(offset))

    elif itype == "push" or itype == "pop":
        if len(operands) != 1:
            raise ValueError(error_invalid_operand_count(mnemonic, 1, len(operands)))
        reg_info = get_reg_info(operands[0])
        if reg_info is None:
            raise ValueError(error_invalid_register("регистра", operands[0], mnemonic))
        reg = reg_info["index"]
        size = reg_info["size"]
        if size not in (64, 32):
            raise ValueError("Инструкция '" + mnemonic + "' поддерживает только 32/64-битные регистры")
        base = 0x50 if itype == "push" else 0x58
        if 0 <= reg <= 7:
            code.append(base + reg)
        elif 8 <= reg <= 15:
            code.extend(b'\x41')
            code.append(base + (reg - 8))
        else:
            raise ValueError("Недопустимый регистр для " + itype)

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
            modrm = 0xC0 | (subop << 3) | (reg & 7)
            code.append(modrm)
        elif size == 32:
            rex = 0x40
            if reg >= 8:
                rex |= 0x01
            if rex != 0x40:
                code.append(rex)
            code.append(0xFF)
            modrm = 0xC0 | (subop << 3) | (reg & 7)
            code.append(modrm)
        elif size == 16:
            code.append(0x66)
            rex = 0x40
            if reg >= 8:
                rex |= 0x01
            if rex != 0x40:
                code.append(rex)
            code.append(0xFF)
            modrm = 0xC0 | (subop << 3) | (reg & 7)
            code.append(modrm)
        elif size == 8:
            # Для 8-битных регистров — всегда регистровый режим (Mod=11)
            if reg_info.get("high8"):
                if reg < 4:
                    code.append(0xFE)
                    modrm = 0xC0 | (subop << 3) | reg
                    code.append(modrm)
                else:
                    raise ValueError("Старшие байты доступны только для первых 4 регистров")
            else:
                if reg < 4:
                    code.append(0xFE)
                    modrm = 0xC0 | (subop << 3) | reg
                    code.append(modrm)
                else:
                    rex = 0x40
                    if reg >= 8:
                        rex |= 0x01
                    code.append(rex)
                    code.append(0xFE)
                    modrm = 0xC0 | (subop << 3) | (reg & 7)
                    code.append(modrm)
        else:
            raise ValueError("Неподдерживаемый размер регистра")

    elif itype in ("unary", "muldiv"):
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
            code.append(0xF7)
            modrm = 0xC0 | (subop << 3) | (reg & 7)
            code.append(modrm)
        elif size == 32:
            rex = 0x40
            if reg >= 8:
                rex |= 0x01
            if rex != 0x40:
                code.append(rex)
            code.append(0xF7)
            modrm = 0xC0 | (subop << 3) | (reg & 7)
            code.append(modrm)
        elif size == 16:
            code.append(0x66)
            rex = 0x40
            if reg >= 8:
                rex |= 0x01
            if rex != 0x40:
                code.append(rex)
            code.append(0xF7)
            modrm = 0xC0 | (subop << 3) | (reg & 7)
            code.append(modrm)
        elif size == 8:
            if reg_info.get("high8"):
                if reg < 4:
                    code.append(0xF6)
                    modrm = 0xC0 | (subop << 3) | reg
                    code.append(modrm)
                else:
                    raise ValueError("Старшие байты только для первых 4 регистров")
            else:
                if reg < 4:
                    code.append(0xF6)
                    modrm = 0xC0 | (subop << 3) | reg
                    code.append(modrm)
                else:
                    rex = 0x40
                    if reg >= 8:
                        rex |= 0x01
                    code.append(rex)
                    code.append(0xF6)
                    modrm = 0xC0 | (subop << 3) | (reg & 7)
                    code.append(modrm)
        else:
            raise ValueError("Неподдерживаемый размер регистра")

    elif itype == "test":
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
            raise ValueError("Размеры операндов не совпадают в '" + mnemonic + "'")

        if size == 64:
            rex = 0x48
            if src >= 8:
                rex |= 0x04
            if dst >= 8:
                rex |= 0x01
            code.append(rex)
            code.append(0x85)
        elif size == 32:
            rex = 0x40
            if src >= 8:
                rex |= 0x04
            if dst >= 8:
                rex |= 0x01
            if rex != 0x40:
                code.append(rex)
            code.append(0x85)
        elif size == 16:
            code.append(0x66)
            rex = 0x40
            if src >= 8:
                rex |= 0x04
            if dst >= 8:
                rex |= 0x01
            if rex != 0x40:
                code.append(rex)
            code.append(0x85)
        elif size == 8:
            if dst_info.get("high8") or src_info.get("high8"):
                if rex != 0x40:
                    raise ValueError("Старшие байты несовместимы с REX")
                code.append(0x84)
            else:
                rex = 0x40
                if src >= 8:
                    rex |= 0x04
                if dst >= 8:
                    rex |= 0x01
                if rex != 0x40:
                    code.append(rex)
                code.append(0x84)
        else:
            raise ValueError("Неподдерживаемый размер регистра")
        modrm = 0xC0 | ((src & 7) << 3) | (dst & 7)
        code.append(modrm)

    elif itype == "lea":
        if len(operands) != 2:
            raise ValueError(error_invalid_operand_count(mnemonic, 2, len(operands)))
        dst_info = get_reg_info(operands[0])
        label = operands[1]
        if dst_info is None:
            raise ValueError(error_invalid_register("назначения", operands[0], mnemonic))
        if label not in labels:
            raise ValueError(error_missing_label(label))
        dst = dst_info["index"]
        if dst_info["size"] != 64:
            raise ValueError("LEA поддерживает только 64-битные регистры назначения")
        target_addr = parse_operand(label)
        current_addr = vaddr_text + position[".text"]
        rip_after = current_addr + 7
        disp = target_addr - rip_after
        if disp < -0x80000000 or disp > 0x7FFFFFFF:
            raise ValueError("Метка слишком далеко для RIP-relative адресации: " + label)
        code.extend(b"\x48\x8D")
        modrm = 0x05 | ((dst & 7) << 3)
        if dst >= 8:
            code[0] |= 0x01
        code.append(modrm)
        code.extend(pack_i32_le(disp))

    elif itype in ("shift_imm", "rotate_imm"):
        if len(operands) != 2:
            raise ValueError(error_invalid_operand_count(mnemonic, 2, len(operands)))
        reg_info = get_reg_info(operands[0])
        if reg_info is None:
            raise ValueError(error_invalid_register("регистра", operands[0], mnemonic))
        imm = parse_operand(operands[1])
        if not (0 <= imm <= 255):
            raise ValueError("Сдвиг/вращение должно быть в диапазоне 0–255, получено: " + str(imm))
        reg = reg_info["index"]
        size = reg_info["size"]
        base_op = instr["code"][-1]  # последний байт — базовый опкод без регистра

        if size == 64:
            rex = 0x48
            if reg >= 8:
                rex |= 0x01
            code.append(rex)
            code.append(0xC1)
            modrm = 0xC0 | (base_op << 3) | (reg & 7)
            code.append(modrm)
            code.append(imm & 0xFF)
        elif size == 32:
            rex = 0x40
            if reg >= 8:
                rex |= 0x01
            if rex != 0x40:
                code.append(rex)
            code.append(0xC1)
            modrm = 0xC0 | (base_op << 3) | (reg & 7)
            code.append(modrm)
            code.append(imm & 0xFF)
        elif size == 16:
            code.append(0x66)
            rex = 0x40
            if reg >= 8:
                rex |= 0x01
            if rex != 0x40:
                code.append(rex)
            code.append(0xC1)
            modrm = 0xC0 | (base_op << 3) | (reg & 7)
            code.append(modrm)
            code.append(imm & 0xFF)
        elif size == 8:
            if reg_info.get("high8"):
                if reg < 4:
                    code.append(0xC0)
                    modrm = 0xC0 | (base_op << 3) | reg
                    code.append(modrm)
                    code.append(imm & 0xFF)
                else:
                    raise ValueError("Старшие байты только для первых 4 регистров")
            else:
                if reg < 4:
                    code.append(0xC0)
                    modrm = 0xC0 | (base_op << 3) | reg
                    code.append(modrm)
                    code.append(imm & 0xFF)
                else:
                    rex = 0x40
                    if reg >= 8:
                        rex |= 0x01
                    code.append(rex)
                    code.append(0xC0)
                    modrm = 0xC0 | (base_op << 3) | (reg & 7)
                    code.append(modrm)
                    code.append(imm & 0xFF)
        else:
            raise ValueError("Неподдерживаемый размер регистра")

    elif itype == "int":
        if len(operands) != 1:
            raise ValueError(error_invalid_operand_count(mnemonic, 1, len(operands)))
        imm = parse_operand(operands[0])
        if not (0 <= imm <= 255):
            raise ValueError("Номер прерывания должен быть 0–255, получено: " + str(imm))
        code.extend(instr["code"])
        code.append(imm & 0xFF)

    elif itype in ("movzx", "movsx"):
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
        if dst_info["size"] != 64:
            raise ValueError("Назначение в '" + mnemonic + "' должно быть 64-битным")
        if src_info["size"] not in (8, 16):
            raise ValueError("Источник в '" + mnemonic + "' должен быть 8- или 16-битным")

        rex = 0x48
        if src >= 8:
            rex |= 0x04
        if dst >= 8:
            rex |= 0x01
        code.append(rex)
        code.extend(instr["code"][1:])  # пропускаем 0x48 из оригинального опкода
        modrm = 0xC0 | ((src & 7) << 3) | (dst & 7)
        code.append(modrm)

    elif itype == "xchg":
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
            raise ValueError("Размеры операндов не совпадают в '" + mnemonic + "'")

        if size == 64:
            rex = 0x48
            if src >= 8:
                rex |= 0x04
            if dst >= 8:
                rex |= 0x01
            code.append(rex)
            code.append(0x87)
        elif size == 32:
            rex = 0x40
            if src >= 8:
                rex |= 0x04
            if dst >= 8:
                rex |= 0x01
            if rex != 0x40:
                code.append(rex)
            code.append(0x87)
        elif size == 16:
            code.append(0x66)
            rex = 0x40
            if src >= 8:
                rex |= 0x04
            if dst >= 8:
                rex |= 0x01
            if rex != 0x40:
                code.append(rex)
            code.append(0x87)
        elif size == 8:
            if dst_info.get("high8") or src_info.get("high8"):
                code.append(0x86)
            else:
                rex = 0x40
                if src >= 8:
                    rex |= 0x04
                if dst >= 8:
                    rex |= 0x01
                if rex != 0x40:
                    code.append(rex)
                code.append(0x86)
        else:
            raise ValueError("Неподдерживаемый размер регистра")
        modrm = 0xC0 | ((src & 7) << 3) | (dst & 7)
        code.append(modrm)

    elif itype == "loop":
        if len(operands) != 1:
            raise ValueError(error_invalid_operand_count(mnemonic, 1, len(operands)))
        code.extend(instr["code"])
        target = parse_operand(operands[0])
        current_addr = vaddr_text + position[".text"]
        offset = (target - (current_addr + 2)) & 0xFF
        if not (0 <= offset <= 255):
            raise ValueError("Цель цикла слишком далеко")
        code.append(offset & 0xFF)

    elif itype == "mov_reg8_imm8":
        # Обрабатывается в reg_imm, но оставлено для совместимости
        raise ValueError("Используйте 'переместить_имм' вместо 'загрузить_байт'")

    elif itype in ("add_reg8_reg8", "sub_reg8_reg8", "cmp_reg8_reg8"):
        if len(operands) != 2:
            raise ValueError(error_invalid_operand_count(mnemonic, 2, len(operands)))
        dst_info = get_reg_info(operands[0])
        src_info = get_reg_info(operands[1])
        if dst_info is None:
            raise ValueError(error_invalid_register("назначения", operands[0], mnemonic))
        if src_info is None:
            raise ValueError(error_invalid_register("источника", operands[1], mnemonic))
        if dst_info["size"] != 8 or src_info["size"] != 8:
            raise ValueError("Операнды должны быть 8-битными в '" + mnemonic + "'")
        dst = dst_info["index"]
        src = src_info["index"]

        op_map = {
            "add_reg8_reg8": 0x00,
            "sub_reg8_reg8": 0x28,
            "cmp_reg8_reg8": 0x38,
        }
        op = op_map[itype]

        if dst_info.get("high8") or src_info.get("high8"):
            if dst >= 4 or src >= 4:
                raise ValueError("Старшие байты доступны только для первых 4 регистров")
            code.append(op)
            modrm = 0xC0 | (src << 3) | dst
            code.append(modrm)
        else:
            rex = 0x40
            if src >= 8:
                rex |= 0x04
            if dst >= 8:
                rex |= 0x01
            if rex != 0x40:
                code.append(rex)
            code.append(op)
            modrm = 0xC0 | ((src & 7) << 3) | (dst & 7)
            code.append(modrm)

    elif itype in ("mov_mem8_reg8", "store_reg8_to_reg64"):
        if len(operands) != 2:
            raise ValueError(error_invalid_operand_count(mnemonic, 2, len(operands)))
        addr_op = operands[0]
        src_info = get_reg_info(operands[1])
        if not (addr_op.startswith('[') and addr_op.endswith(']')):
            raise ValueError(error_invalid_address_operand(addr_op))
        base_name = addr_op[1:-1]
        base_info = get_reg_info(base_name)
        if base_info is None:
            raise ValueError(error_invalid_register("адресного регистра", base_name, mnemonic))
        if src_info is None:
            raise ValueError(error_invalid_register("источника", operands[1], mnemonic))
        if base_info["size"] != 64:
            raise ValueError("Адресный регистр должен быть 64-битным")
        if src_info["size"] != 8:
            raise ValueError("Источник должен быть 8-битным")

        base = base_info["index"]
        src = src_info["index"]

        if src_info.get("high8"):
            if src >= 4:
                raise ValueError("Старшие байты только для первых 4 регистров")
            code.append(0x88)
            modrm = 0x00 | (src << 3) | base
            code.append(modrm)
        else:
            rex = 0x40
            if src >= 8:
                rex |= 0x04
            if base >= 8:
                rex |= 0x01
            if rex != 0x40:
                code.append(rex)
            code.append(0x88)
            modrm = 0x00 | ((src & 7) << 3) | (base & 7)
            code.append(modrm)

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
                code.extend(pack_u32_le(imm & 0xFFFFFFFF))
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
                code.extend(pack_u32_le(imm & 0xFFFFFFFF))
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
                raise ValueError("8-битное значение вне диапазона 0–255: " + str(imm))
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

    elif itype in ("mov_reg_mem", "mov_mem_reg", "xchg_mem_reg"):
        if len(operands) != 2:
            raise ValueError(error_invalid_operand_count(mnemonic, 2, len(operands)))
        if itype in ("mov_reg_mem", "xchg_mem_reg"):
            dst_info = get_reg_info(operands[0])
            src_op = operands[1]
            is_load = True
        else:  # mov_mem_reg
            dst_op = operands[0]
            src_info = get_reg_info(operands[1])
            is_load = False

        if is_load:
            if not (src_op.startswith('[') and src_op.endswith(']')):
                raise ValueError(error_invalid_address_operand(src_op))
            base_name = src_op[1:-1]
            base_info = get_reg_info(base_name)
            if base_info is None:
                raise ValueError(error_invalid_register("базового адреса", base_name, mnemonic))
            if dst_info is None:
                raise ValueError(error_invalid_register("назначения", operands[0], mnemonic))
            if base_info["size"] != 64:
                raise ValueError("Адресный регистр должен быть 64-битным")
            dst = dst_info["index"]
            base = base_info["index"]
            size = dst_info["size"]
        else:
            if not (dst_op.startswith('[') and dst_op.endswith(']')):
                raise ValueError(error_invalid_address_operand(dst_op))
            base_name = dst_op[1:-1]
            base_info = get_reg_info(base_name)
            if base_info is None:
                raise ValueError(error_invalid_register("адресного регистра", base_name, mnemonic))
            if src_info is None:
                raise ValueError(error_invalid_register("источника", operands[1], mnemonic))
            if base_info["size"] != 64:
                raise ValueError("Адресный регистр должен быть 64-битным")
            src = src_info["index"]
            base = base_info["index"]
            size = src_info["size"]

        op_map = {
            "mov_reg_mem": (0x8B, True),
            "mov_mem_reg": (0x89, False),
            "xchg_mem_reg": (0x87, False),
        }
        op, is_load_op = op_map[itype]

        if size == 64:
            rex = 0x48
            if base >= 8:
                rex |= 0x01
            if (is_load and dst >= 8) or (not is_load and src >= 8):
                rex |= 0x04
            code.append(rex)
            code.append(op)
        elif size == 32:
            rex = 0x40
            if base >= 8:
                rex |= 0x01
            if (is_load and dst >= 8) or (not is_load and src >= 8):
                rex |= 0x04
            if rex != 0x40:
                code.append(rex)
            code.append(op)
        elif size == 16:
            code.append(0x66)
            rex = 0x40
            if base >= 8:
                rex |= 0x01
            if (is_load and dst >= 8) or (not is_load and src >= 8):
                rex |= 0x04
            if rex != 0x40:
                code.append(rex)
            code.append(op)
        elif size == 8:
            if is_load:
                raise ValueError("Загрузка 8-битного регистра из памяти не поддерживается напрямую в этом ассемблере")
            else:
                if src_info.get("high8"):
                    if src >= 4:
                        raise ValueError("Старшие байты только для первых 4 регистров")
                    code.append(0x88)
                    modrm = 0x00 | (src << 3) | base
                    code.append(modrm)
                    return bytes(code)
                else:
                    rex = 0x40
                    if src >= 8:
                        rex |= 0x04
                    if base >= 8:
                        rex |= 0x01
                    if rex != 0x40:
                        code.append(rex)
                    code.append(0x88)
                    modrm = 0x00 | ((src & 7) << 3) | (base & 7)
                    code.append(modrm)
                    return bytes(code)
        else:
            raise ValueError("Неподдерживаемый размер регистра")

        modrm = 0x00 | (((dst if is_load else src) & 7) << 3) | (base & 7)
        code.append(modrm)

    elif itype in ("mov32_reg_reg", "add32_reg_reg", "sub32_reg_reg", "cmp32_reg_reg"):
        if len(operands) != 2:
            raise ValueError(error_invalid_operand_count(mnemonic, 2, len(operands)))
        dst_info = get_reg_info(operands[0])
        src_info = get_reg_info(operands[1])
        if dst_info is None:
            raise ValueError(error_invalid_register("назначения", operands[0], mnemonic))
        if src_info is None:
            raise ValueError(error_invalid_register("источника", operands[1], mnemonic))
        if dst_info["size"] != 32 or src_info["size"] != 32:
            raise ValueError("Операнды должны быть 32-битными в '" + mnemonic + "'")
        dst = dst_info["index"]
        src = src_info["index"]

        op_map = {
            "mov32_reg_reg": 0x89,
            "add32_reg_reg": 0x01,
            "sub32_reg_reg": 0x29,
            "cmp32_reg_reg": 0x39,
        }
        op = op_map[itype]

        rex = 0x40
        if src >= 8:
            rex |= 0x04
        if dst >= 8:
            rex |= 0x01
        if rex != 0x40:
            code.append(rex)
        code.append(op)
        modrm = 0xC0 | ((src & 7) << 3) | (dst & 7)
        code.append(modrm)

    elif itype in ("add_reg_imm", "sub_reg_imm"):
        if len(operands) != 2:
            raise ValueError(error_invalid_operand_count(mnemonic, 2, len(operands)))
        reg_info = get_reg_info(operands[0])
        if reg_info is None:
            raise ValueError(error_invalid_register("регистра", operands[0], mnemonic))
        reg = reg_info["index"]
        size = reg_info["size"]
        imm = parse_operand(operands[1])

        is_add = (itype == "add_reg_imm")
        if size == 64:
            if -128 <= imm <= 127:
                rex = 0x48
                if reg >= 8:
                    rex |= 0x01
                code.append(rex)
                code.append(0x83)
                modrm = 0xC0 | (reg & 7) if is_add else 0xE8 | (reg & 7)
                code.append(modrm)
                code.append(imm & 0xFF)
            elif -0x80000000 <= imm <= 0x7FFFFFFF:
                rex = 0x48
                if reg >= 8:
                    rex |= 0x01
                code.append(rex)
                code.append(0x81)
                modrm = 0xC0 | (reg & 7) if is_add else 0xE8 | (reg & 7)
                code.append(modrm)
                code.extend(pack_u32_le(imm & 0xFFFFFFFF))
            else:
                raise ValueError(("Непосредственное значение слишком велико для " + ("сложения" if is_add else "вычитания")) + ": " + str(imm))
        elif size == 32:
            if -128 <= imm <= 127:
                rex = 0x40
                if reg >= 8:
                    rex |= 0x01
                if rex != 0x40:
                    code.append(rex)
                code.append(0x83)
                modrm = 0xC0 | (reg & 7) if is_add else 0xE8 | (reg & 7)
                code.append(modrm)
                code.append(imm & 0xFF)
            elif -0x80000000 <= imm <= 0x7FFFFFFF:
                rex = 0x40
                if reg >= 8:
                    rex |= 0x01
                if rex != 0x40:
                    code.append(rex)
                code.append(0x81)
                modrm = 0xC0 | (reg & 7) if is_add else 0xE8 | (reg & 7)
                code.append(modrm)
                code.extend(pack_u32_le(imm & 0xFFFFFFFF))
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
                modrm = 0xC0 | (reg & 7) if is_add else 0xE8 | (reg & 7)
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
                modrm = 0xC0 | (reg & 7) if is_add else 0xE8 | (reg & 7)
                code.append(modrm)
                code.append(imm & 0xFF)
                code.append((imm >> 8) & 0xFF)
            else:
                raise ValueError("16-битное непосредственное значение вне диапазона")
        elif size == 8:
            if not (0 <= imm <= 255):
                raise ValueError("8-битное значение вне диапазона 0–255: " + str(imm))
            if reg_info.get("high8"):
                if reg < 4:
                    code.append(0x80)
                    modrm = (0xC0 if is_add else 0xE8) | reg
                    code.append(modrm)
                    code.append(imm & 0xFF)
                else:
                    raise ValueError("Старшие байты только для первых 4 регистров")
            else:
                if reg < 4:
                    code.append(0x80)
                    modrm = (0xC0 if is_add else 0xE8) | reg
                    code.append(modrm)
                    code.append(imm & 0xFF)
                else:
                    rex = 0x40
                    if reg >= 8:
                        rex |= 0x01
                    code.append(rex)
                    code.append(0x80)
                    modrm = (0xC0 if is_add else 0xE8) | (reg & 7)
                    code.append(modrm)
                    code.append(imm & 0xFF)
        else:
            raise ValueError("Неподдерживаемый размер регистра")

    elif itype == "xor_self":
        if len(operands) != 1:
            raise ValueError(error_invalid_operand_count(mnemonic, 1, len(operands)))
        reg_info = get_reg_info(operands[0])
        if reg_info is None:
            raise ValueError(error_invalid_register("регистра", operands[0], mnemonic))
        reg = reg_info["index"]
        size = reg_info["size"]
        if size == 64:
            rex = 0x48
            if reg >= 8:
                rex |= 0x01
            code.append(rex)
            code.append(0x31)
        elif size == 32:
            rex = 0x40
            if reg >= 8:
                rex |= 0x01
            if rex != 0x40:
                code.append(rex)
            code.append(0x31)
        elif size == 16:
            code.append(0x66)
            rex = 0x40
            if reg >= 8:
                rex |= 0x01
            if rex != 0x40:
                code.append(rex)
            code.append(0x31)
        elif size == 8:
            if reg_info.get("high8"):
                code.append(0x30)
            else:
                rex = 0x40
                if reg >= 8:
                    rex |= 0x01
                if rex != 0x40:
                    code.append(rex)
                code.append(0x30)
        else:
            raise ValueError("Неподдерживаемый размер регистра")
        modrm = 0xC0 | ((reg & 7) << 3) | (reg & 7)
        code.append(modrm)
    
    

    elif itype in ("push_mem", "pop_mem"):
        if len(operands) != 1:
            raise ValueError(error_invalid_operand_count(mnemonic, 1, len(operands)))
        addr_op = operands[0]
        if not (addr_op.startswith('[') and addr_op.endswith(']')):
            raise ValueError(error_invalid_address_operand(addr_op))
        base_name = addr_op[1:-1]
        base_info = get_reg_info(base_name)
        if base_info is None:
            raise ValueError(error_invalid_register("адресного регистра", base_name, mnemonic))
        if base_info["size"] != 64:
            raise ValueError("Адресный регистр должен быть 64-битным")
        base = base_info["index"]

        # REX префикс - только если нужен B бит для расширенных регистров
        rex = 0x40
        if base >= 8:
            rex |= 0x01
        # НЕ устанавливаем REX.W бит (0x08) - он не нужен для push/pop с памятью

        op = 0xFF if itype == "push_mem" else 0x8F
        subop = 6 if itype == "push_mem" else 0

        # Специальные случаи:
        if base == 4 or base == 12:  # rsp или r12 - требуют SIB
            if rex != 0x40:
                code.append(rex)
            code.append(op)
            code.append(0x24)  # ModR/M: mod=00, reg=subop, r/m=100 (SIB required)
            code.append(0x24)  # SIB: scale=00, index=100, base=100 ([rsp]/[r12])
        elif base == 5 or base == 13:  # rbp или r13 - требуют 8-битного нулевого смещения
            if rex != 0x40:
                code.append(rex)
            code.append(op)
            code.append(0x40 | (subop << 3) | (base & 7))  # ModR/M: mod=01, reg=subop, r/m=base
            code.append(0x00)  # disp8 = 0
        else:
            # Обычные регистры
            if rex != 0x40:
                code.append(rex)
            code.append(op)
            modrm = (subop << 3) | (base & 7)
            code.append(modrm)








    elif itype in ("in_imm", "out_imm"):
        if len(operands) != 1:
            raise ValueError(error_invalid_operand_count(mnemonic, 1, len(operands)))
        imm = parse_operand(operands[0])
        if not (0 <= imm <= 255):
            raise ValueError(("Порт " + ("ввода" if itype == "in_imm" else "вывода") + " должен быть 0–255: ") + str(imm))
        code.append(instr["code"][0])
        code.append(imm & 0xFF)

    elif itype == "short_jmp":
        if len(operands) != 1:
            raise ValueError(error_invalid_operand_count(mnemonic, 1, len(operands)))
        target = parse_operand(operands[0])
        current_addr = vaddr_text + position[".text"]
        offset = target - (current_addr + 2)
        if not (-128 <= offset <= 127):
            raise ValueError("Цель слишком далеко для короткого перехода: " + str(offset))
        code.append(0xEB)
        code.append(offset & 0xFF)

    else:
        raise ValueError("Неизвестный тип инструкции: " + itype)

    return bytes(code)



def parse_instruction_or_directive(tokens, line_num, line_text):
    global current_section, entry_point
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
        elif word == '.константа':
            if len(tokens) < 3:
                raise ValueError(".константа требует имя и значение")
            name = tokens[1][1]
            value = parse_number_token(tokens[2])
            symbols[name] = value
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
        elif word == '.байт':
            if len(tokens) < 2:
                raise ValueError(".байт требует хотя бы один байт")
            for i in range(1, len(tokens)):
                tok = tokens[i]
                if tok[0] != 'word':
                    raise ValueError(error_unexpected_string_in_byte())
                s = tok[1]
                if s.startswith("0x"):
                    try:
                        val = int(s, 16)
                    except:
                        raise ValueError(error_invalid_number_format(s))
                elif s.isdigit():
                    try:
                        val = int(s)
                    except:
                        raise ValueError(error_invalid_number_format(s))
                else:
                    raise ValueError(error_invalid_number_format(s))
                if val < 0 or val > 255:
                    raise ValueError(error_byte_out_of_range(s, val))
                if pass_num == 2:
                    sections[current_section].append(val)
                else:
                    position[current_section] += 1
            return
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
            raise ValueError(error_unexpected_token_in_operands(tok))

    if pass_num == 2:
        code = encode_instruction(mnemonic, operands, line_num, line_text)
        sections[current_section] += code
        position[current_section] += len(code)
    else:
        instr_info = INSTRUCTIONS[mnemonic]
        itype = instr_info["type"]
        size_map = {
            "reg_imm": 10,
            "reg_reg": 3,
            "test": 3,
            "call": 5,
            "jmp": 5,
            "jcc": 6,
            "push": 1,
            "pop": 1,
            "none": lambda: len(instr_info["code"]),
            "incdec": 3,
            "unary": 3,
            "muldiv": 3,
            "shift_imm": 4,
            "rotate_imm": 4,
            "int": 2,
            "lea": 7,
            "movzx": 4,
            "movsx": 4,
            "xchg": 3,
            "loop": 2,
            "mov_reg8_imm8": 3,
            "add_reg8_reg8": 3,
            "mov_mem8_reg8": 3,
            "store_reg8_to_reg64": 3,

            "cmp_reg_imm": 7,          # REX + 0x81 + ModR/M + imm32
            "mov_reg_mem": 3,          # REX + 0x8B + ModR/M
            "mov_mem_reg": 3,          # REX + 0x89 + ModR/M
            "xchg_mem_reg": 3,         # REX + 0x87 + ModR/M
            "mov32_reg_reg": 3,        # REX + 0x89 + ModR/M
            "add32_reg_reg": 3,        # REX + 0x01 + ModR/M
            "sub32_reg_reg": 3,        # REX + 0x29 + ModR/M
            "cmp32_reg_reg": 3,        # REX + 0x39 + ModR/M
            "sub_reg8_reg8": 3,        # REX + 0x28 + ModR/M
            "cmp_reg8_reg8": 3,        # REX + 0x38 + ModR/M
            "add_reg_imm": 7,          # REX + 0x81 + ModR/M + imm32
            "sub_reg_imm": 7,          # REX + 0x81 + ModR/M + imm32
            "xor_self": 3,             # REX + 0x31 + ModR/M
            "push_mem": 4,             # REX + 0xFF + ModR/M (/6)
            "pop_mem": 4,              # REX + 0x8F + ModR/M (/0)   
            "in_imm": 2,               # 0xE4 + imm8
            "out_imm": 2,              # 0xE6 + imm8
            "short_jmp": 2,            # 0xEB + disp8
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
    global pass_num, text_size, data_size, vaddr_text, vaddr_data
    global offset_text, offset_data, memsz_text, memsz_data
    global sections, position
    lines = source.split('\n')
    # === ПРОХОД 1: анализ ===
    pass_num = 1
    position[".text"] = 0
    position[".data"] = 0
    sections[".text"] = bytearray()
    sections[".data"] = bytearray()
    log("=== ПРОХОД 1: анализ ===")
    for line_num, line in enumerate(lines, start=1):
        original_line = line.rstrip()
        log("[ПРОХОД 1] Line " + str(line_num) + ": " + original_line)
        try:
            tokens = tokenize_line(line)
            log_tokens(line_num, tokens)
            parse_tokens(tokens, line_num, original_line)
        except Exception as e:
            error_full = make_error_msg(line_num, original_line, str(e))
            log("ОШИБКА на проходе 1:\n" + error_full)
            print(error_full, file=sys.stderr)
            close_log()
            sys.exit(1)
    text_size = position[".text"]
    data_size = position[".data"]
    PAGE_SIZE = 0x1000
    elf_header_size = 64
    program_header_size = 56
    ph_num = 2
    ph_table_size = program_header_size * ph_num
    offset_text = align_up(elf_header_size + ph_table_size, PAGE_SIZE)
    offset_data = align_up(offset_text + text_size, PAGE_SIZE)
    vaddr_text = code_start
    memsz_text = align_up(text_size, PAGE_SIZE)
    vaddr_data = align_up(vaddr_text + memsz_text, PAGE_SIZE)
    memsz_data = align_up(data_size, PAGE_SIZE)
    log("Вычисленные адреса:")
    log(".text offset = " + hex(offset_text) + ", vaddr = " + hex(vaddr_text) +
        ", size = " + str(text_size) + ", memsz = " + str(memsz_text))
    log(".data offset = " + hex(offset_data) + ", vaddr = " + hex(vaddr_data) +
        ", size = " + str(data_size) + ", memsz = " + str(memsz_data))
    # === ПРОХОД 2: генерация ===
    pass_num = 2
    position[".text"] = 0
    position[".data"] = 0
    sections[".text"] = bytearray()
    sections[".data"] = bytearray()
    log("=== ПРОХОД 2: генерация ===")
    for line_num, line in enumerate(lines, start=1):
        original_line = line.rstrip()
        log("[ПРОХОД 2] Line " + str(line_num) + ": " + original_line)
        try:
            tokens = tokenize_line(line)
            log_tokens(line_num, tokens)
            parse_tokens(tokens, line_num, original_line)
        except Exception as e:
            error_full = make_error_msg(line_num, original_line, str(e))
            log("ОШИБКА на проходе 2:\n" + error_full)
            print(error_full, file=sys.stderr)
            close_log()
            sys.exit(1)
    log_labels()

# === ELF ===

def create_elf(filename):
    global sections, entry_point, labels, vaddr_text
    global offset_text, offset_data, vaddr_data, memsz_text, memsz_data
    text = sections[".text"]
    data = sections[".data"]
    entry_addr = vaddr_text + labels.get(entry_point, 0)

    e_ident = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    e_type = pack_u16_le(2)
    e_machine = pack_u16_le(0x3E)
    e_version = pack_u32_le(1)
    e_entry = pack_u64_le(entry_addr)
    e_phoff = pack_u64_le(64)
    e_shoff = pack_u64_le(0)
    e_flags = pack_u32_le(0)
    e_ehsize = pack_u16_le(64)
    e_phentsize = pack_u16_le(56)
    e_phnum = pack_u16_le(2)
    e_shentsize = pack_u16_le(0)
    e_shnum = pack_u16_le(0)
    e_shstrndx = pack_u16_le(0)

    elf_header = (
        e_ident +
        e_type + e_machine + e_version +
        e_entry + e_phoff + e_shoff +
        e_flags +
        e_ehsize + e_phentsize + e_phnum +
        e_shentsize + e_shnum + e_shstrndx
    )

    p_type = pack_u32_le(1)
    p_flags = pack_u32_le(5)
    p_offset = pack_u64_le(offset_text)
    p_vaddr = pack_u64_le(vaddr_text)
    p_paddr = pack_u64_le(vaddr_text)
    p_filesz = pack_u64_le(len(text))
    p_memsz = pack_u64_le(memsz_text)
    p_align = pack_u64_le(0x1000)

    text_header = (
        p_type + p_flags +
        p_offset + p_vaddr + p_paddr +
        p_filesz + p_memsz + p_align
    )

    p_flags_data = pack_u32_le(6)
    p_offset_data = pack_u64_le(offset_data)
    p_vaddr_data = pack_u64_le(vaddr_data)
    p_paddr_data = pack_u64_le(vaddr_data)
    p_filesz_data = pack_u64_le(len(data))
    p_memsz_data = pack_u64_le(memsz_data)

    data_header = (
        p_type + p_flags_data +
        p_offset_data + p_vaddr_data + p_paddr_data +
        p_filesz_data + p_memsz_data + p_align
    )

    file_content = bytearray()
    file_content.extend(elf_header)
    file_content.extend(text_header)
    file_content.extend(data_header)

    while len(file_content) < offset_text:
        file_content.append(0)
    file_content.extend(text)

    while len(file_content) < offset_data:
        file_content.append(0)
    file_content.extend(data)

    f_out = open(filename, "wb")
    f_out.write(file_content)
    f_out.close()

    import os
    os.chmod(filename, 0o755)

# === Основной запуск ===

if len(sys.argv) != 2:
    print("Использование: python asm3_full_two_pass.py <файл.квс>")
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

log_file = open("asm_log.txt", "w", encoding="utf-8")
tokens_log = open("tokens.log", "w", encoding="utf-8")

try:
    parse(source)
    elf_file = source_file[:-4] + ".elf"
    create_elf(elf_file)
    close_log()
    print("ELF-файл успешно создан: " + elf_file)
    print("Токены сохранены в tokens.log")
    print("Запустите: ./" + elf_file)
except SystemExit:
    raise
except Exception as e:
    close_log()
    print("Внутренняя ошибка ассемблера (сообщите разработчику, ну или сами как-нить ...): " + str(e), file=sys.stderr)
    sys.exit(1)
