#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
kvs_9_8.py
КВС - язык программирования
- не использовать re
- использовать только struct для упаковки данных
- оформлять самодокументируемый код
- комментарии на русском
- dry вреден, изоляция логики уместна
- избегать ооп (имеем в виду возможную самокомпиляцию)
- добавить поиск модулей по абсолютным и относительным путям
- готовить внедрение сложной адресации
"""

import sys
import struct
import os

source_filename = ""

def safe_close(f):
    if f is not None:
        f.close()

# === ГЛОБАЛЬНЫЕ ДАННЫЕ: ПОЛНЫЙ НАБОР КОМАНД ===
INSTRUCTIONS = {
    # Инструкции перемещения данных
    "переместить": {"code": b"\x48\x89", "type": "reg_reg"},                            # MOV       - переместить данные между регистрами
    "переместить_имм": {"code": None, "type": "reg_imm"},                               # MOV       - переместить непосредственное значение в регистр
    "загрузить": {"code": b"\x48\x8B", "type": "mov_reg_mem"},                          # MOV       - загрузить из памяти      [МОЖНО ВНЕДРИТЬ СЛОЖНУЮ АДРЕСАЦИЮ]
    "сохранить": {"code": b"\x48\x89", "type": "mov_mem_reg"},                          # MOV       - сохранить в память       [МОЖНО ВНЕДРИТЬ СЛОЖНУЮ АДРЕСАЦИЮ]
    "загрузить_байт_из_памяти": {"code": b"\x8A", "type": "mov_reg8_mem"},              # MOV       - загрузить байт из памяти [МОЖНО ВНЕДРИТЬ СЛОЖНУЮ АДРЕСАЦИЮ]
    "сохранить_байт": {"code": b"\x88", "type": "mov_mem8_reg8"},                       # MOV       - сохранить байт в память  [МОЖНО ВНЕДРИТЬ СЛОЖНУЮ АДРЕСАЦИЮ]
    "сохранить_в_адрес": {"code": b"\x88", "type": "store_reg8_to_reg64"},              # MOV       - сохранить байт по адресу [МОЖНО ВНЕДРИТЬ СЛОЖНУЮ АДРЕСАЦИЮ]
    "загрузить_адрес": {"code": b"\x48\x8D", "type": "lea"},                            # LEA       - загрузить эффективный адрес
    "переместить_с_нулями": {"code": b"\x48\x0F\xB6", "type": "movzx"},                 # MOVZX     - переместить с расширением нулями
    "переместить_со_знаком": {"code": b"\x48\x0F\xBE", "type": "movsx"},                # MOVSX     - переместить с расширением знака

    # Арифметические инструкции
    "прибавить": {"code": b"\x48\x01", "type": "reg_reg"},                              # ADD       - сложить регистры
    "вычесть": {"code": b"\x48\x29", "type": "reg_reg"},                                # SUB       - вычесть регистры
    "прибавить_непосредственно": {"code": None, "type": "add_reg_imm"},                 # ADD       - прибавить непосредственное значение к регистру
    "вычесть_непосредственно": {"code": None, "type": "sub_reg_imm"},                   # SUB       - вычесть непосредственное значение из регистра
    "прибавить_байт": {"code": b"\x00", "type": "add_reg8_reg8"},                       # ADD       - сложить байтовые регистры
    "вычесть_байт": {"code": b"\x28", "type": "sub_reg8_reg8"},                         # SUB       - вычесть байтовые регистры
    "увеличить": {"code": b"\xFF", "subop": 0, "type": "incdec"},                       # INC       - инкремент регистра
    "уменьшить": {"code": b"\xFF", "subop": 1, "type": "incdec"},                       # DEC       - декремент регистра
    "умножить": {"code": b"\xF7", "subop": 4, "type": "muldiv"},                        # MUL       - беззнаковое умножение
    "умножить_знаковое": {"code": b"\xF7", "subop": 5, "type": "muldiv"},               # IMUL      - знаковое умножение
    "разделить": {"code": b"\xF7", "subop": 6, "type": "muldiv"},                       # DIV       - беззнаковое деление
    "разделить_знаковое": {"code": b"\xF7", "subop": 7, "type": "muldiv"},              # IDIV      - знаковое деление

    # Логические инструкции
    "и": {"code": b"\x48\x21", "type": "reg_reg"},                                      # AND       - побитовое И
    "или": {"code": b"\x48\x09", "type": "reg_reg"},                                    # OR        - побитовое ИЛИ
    "исключающее_или": {"code": b"\x48\x31", "type": "reg_reg"},                        # XOR       - побитовое исключающее ИЛИ
    "инвертировать": {"code": b"\xF7", "subop": 2, "type": "unary"},                    # NOT       - побитовое НЕ
    "отрицать": {"code": b"\xF7", "subop": 3, "type": "unary"},                         # NEG       - арифметическое отрицание
    "проверить": {"code": b"\x48\x85", "type": "test"},                                 # TEST      - логическое сравнение
    "очистить": {"code": b"\x48\x31", "type": "xor_self"},                              # XOR       - очистить регистр (XOR с самим собой)

    # Инструкции сравнения
    "сравнить": {"code": b"\x48\x39", "type": "reg_reg"},                               # CMP       - сравнить регистры
    "сравнить_с": {"code": None, "type": "cmp_reg_imm"},                                # CMP       - сравнить регистр с непосредственным значением
    "сравнить_байт": {"code": b"\x38", "type": "cmp_reg8_reg8"},                        # CMP       - сравнить байтовые регистры
    "сравнить_байт_с_нулем": {"code": b"\x80", "subop": 7, "type": "cmp_mem8_imm"},     # CMP       - сравнить байт с нулем [МОЖНО ВНЕДРИТЬ СЛОЖНУЮ АДРЕСАЦИЮ]

    # Инструкции переходов и вызовов
    "вызвать": {"code": b"\xE8", "type": "call"},                                       # CALL      - вызов процедуры
    "вернуться": {"code": b"\xC3", "type": "none"},                                     # RET       - возврат из процедуры
    "переход": {"code": b"\xE9", "type": "jmp"},                                        # JMP       - безусловный переход
    "короткий_переход": {"code": b"\xEB", "type": "short_jmp"},                         # JMP       - короткий безусловный переход
    "переход_если_равно": {"code": b"\x0F\x84", "type": "jcc"},                         # JE/JZ     - переход если равно/ноль
    "переход_если_неравно": {"code": b"\x0F\x85", "type": "jcc"},                       # JNE/JNZ   - переход если не равно/не ноль
    "переход_если_ноль": {"code": b"\x0F\x84", "type": "jcc"},                          # JZ/ZE     - переход если ноль
    "переход_если_не_ноль": {"code": b"\x0F\x85", "type": "jcc"},                       # JNZ/JNE   - переход если не ноль
    "переход_если_меньше": {"code": b"\x0F\x8C", "type": "jcc"},                        # JL        - переход если меньше
    "переход_если_больше": {"code": b"\x0F\x8F", "type": "jcc"},                        # JG        - переход если больше
    "переход_если_меньше_или_равно": {"code": b"\x0F\x8E", "type": "jcc"},              # JLE       - переход если меньше или равно
    "переход_если_больше_или_равно": {"code": b"\x0F\x8D", "type": "jcc"},              # JGE       - переход если больше или равно
    "переход_если_перенос": {"code": b"\x0F\x82", "type": "jcc"},                       # JC        - переход если перенос
    "переход_если_нет_переноса": {"code": b"\x0F\x83", "type": "jcc"},                  # JNC       - переход если нет переноса
    "короткий_переход_если_равно": {"code": b"\x74", "type": "short_jcc"},              # JE/JZ     - короткий переход если равно/ноль
    "короткий_переход_если_неравно": {"code": b"\x75", "type": "short_jcc"},            # JNE/JNZ   - короткий переход если не равно/не ноль
    "короткий_переход_если_меньше": {"code": b"\x7C", "type": "short_jcc"},             # JL        - короткий переход если меньше
    "короткий_переход_если_больше": {"code": b"\x7F", "type": "short_jcc"},             # JG        - короткий переход если больше
    "короткий_переход_если_меньше_или_равно": {"code": b"\x7E", "type": "short_jcc"},   # JLE       - короткий переход если меньше или равно
    "короткий_переход_если_больше_или_равно": {"code": b"\x7D", "type": "short_jcc"},   # JGE       - короткий переход если больше или равно
    "короткий_переход_если_перенос": {"code": b"\x72", "type": "short_jcc"},            # JC        - короткий переход если перенос
    "короткий_переход_если_нет_переноса": {"code": b"\x73", "type": "short_jcc"},       # JNC       - короткий переход если нет переноса
    "короткий_переход_если_ноль": {"code": b"\x74", "type": "short_jcc"},               # JZ        - короткий переход если ноль
    "короткий_переход_если_не_ноль": {"code": b"\x75", "type": "short_jcc"},            # JNZ       - короткий переход если не ноль

    # Стековые инструкции
    "втолкнуть": {"code": b"\x50", "type": "push"},                                     # PUSH      - поместить в стек
    "вытолкнуть": {"code": b"\x58", "type": "pop"},                                     # POP       - извлечь из стека
    "втолкнуть_из_памяти": {"code": b"\xFF", "subop": 6, "type": "push_mem"},           # PUSH      - поместить в стек из памяти   [МОЖНО ВНЕДРИТЬ СЛОЖНУЮ АДРЕСАЦИЮ]
    "вытолкнуть_в_память": {"code": b"\x8F", "subop": 0, "type": "pop_mem"},            # POP       - извлечь из стека в память    [МОЖНО ВНЕДРИТЬ СЛОЖНУЮ АДРЕСАЦИЮ]

    # Инструкции работы с битами
    "сдвиг_влево": {"code": b"\x48\xC1\xE0", "type": "shift_imm"},                      # SHL       - сдвиг влево
    "сдвиг_вправо": {"code": b"\x48\xC1\xE8", "type": "shift_imm"},                     # SHR       - сдвиг вправо
    "сдвиг_арифметический_влево": {"code": b"\x48\xC1\xE0", "type": "shift_imm"},       # SAL       - арифметический сдвиг влево
    "сдвиг_арифметический_вправо": {"code": b"\x48\xC1\xF8", "type": "shift_imm"},      # SAR       - арифметический сдвиг вправо
    "вращать_влево": {"code": b"\x48\xC1\xC0", "type": "rotate_imm"},                   # ROL       - вращение влево
    "вращать_вправо": {"code": b"\x48\xC1\xC8", "type": "rotate_imm"},                  # ROR       - вращение вправо

    # Инструкции управления потоком
    "цикл": {"code": b"\xE2", "type": "loop"},                                          # LOOP      - инструкция цикла
    "обменять": {"code": b"\x48\x87", "type": "xchg"},                                  # XCHG      - обменять
    "обменять_с_памятью": {"code": b"\x48\x87", "type": "xchg_mem_reg"},                # XCHG      - обменять с памятью [МОЖНО ВНЕДРИТЬ СЛОЖНУЮ АДРЕСАЦИЮ]

    # Системные инструкции
    "вызов_системы": {"code": b"\x0F\x05", "type": "none"},                             # SYSCALL   - системный вызов
    "прервать": {"code": b"\xCD", "type": "int"},                                       # INT       - прерывание
    "войти_в_систему": {"code": b"\x0F\x34", "type": "none"},                           # SYSENTER  - вход в систему
    "получить_управление": {"code": b"\x0F\x01\xD0", "type": "none"},                   # GETSEC    - получить безопасность

    # Строковые инструкции
    "переместить_байт": {"code": b"\xA4", "type": "none"},                              # MOVSB     - переместить байтовую строку
    "переместить_слово": {"code": b"\xA5", "type": "none"},                             # MOVSW     - переместить строку слов
    "сравнить_байты": {"code": b"\xA6", "type": "none"},                                # CMPSB     - сравнить байтовые строки
    "сканировать_байт": {"code": b"\xAE", "type": "none"},                              # SCASB     - сканировать байт

    # Инструкции работы с флагами
    "установить_перенос": {"code": b"\xF9", "type": "none"},                            # STC       - установить флаг переноса
    "сбросить_перенос": {"code": b"\xF8", "type": "none"},                              # CLC       - сбросить флаг переноса
    "установить_направление": {"code": b"\xFD", "type": "none"},                        # STD       - установить флаг направления
    "сбросить_направление": {"code": b"\xFC", "type": "none"},                          # CLD       - сбросить флаг направления
    "втолкнуть_флаги": {"code": b"\x9C", "type": "none"},                               # PUSHF     - поместить флаги в стек
    "вытолкнуть_флаги": {"code": b"\x9D", "type": "none"},                              # POPF      - извлечь флаги из стека

    # Инструкции ввода-вывода
    "ввод_байта": {"code": b"\xE4", "type": "in_imm"},                                  # IN        - ввод байта
    "вывод_байта": {"code": b"\xE6", "type": "out_imm"},                                # OUT       - вывод байта

    # Отладочные инструкции
    "отладка": {"code": b"\xCC", "type": "none"},                                       # INT3      - точка останова
    "нет_операции": {"code": b"\x90", "type": "none"},                                  # NOP       - нет операции
    "остановить": {"code": b"\xF4", "type": "none"},                                    # HLT       - остановить процессор

    # Инструкции идентификации процессора
    "идентифицировать_процессор": {"code": b"\x0F\xA2", "type": "none"},                # CPUID     - идентификация процессора
    "прочитать_счетчик": {"code": b"\x0F\x31", "type": "none"},                         # RDTSC     - чтение счетчика времени

    # Байтовые инструкции
    "загрузить_байт": {"code": None, "type": "mov_reg8_imm8"},                          # MOV       - загрузить непосредственный байт в регистр
}

# 64-битные регистры (полная ширина)
REGISTERS = {
    # Полные 64-битные регистры               (RIP и RSP специальные и часто ограничены в некоторых режимах адресации)
    "раикс": 0,  # RAX - аккумуляторный регистр                                     [используется в сложной адресации]
    "рсикс": 1,  # RCX - счетный регистр                                            [используется в сложной адресации]
    "рдикс": 2,  # RDX - регистр данных                                             [используется в сложной адресации]
    "рбикс": 3,  # RBX - базовый регистр                                            [используется в сложной адресации]
    "рсипи": 4,  # RSP - указатель стека    (используется в стековой адресации)     [используется в сложной адресации]
    "рбипи": 5,  # RBP - базовый указатель  (используется в базовой адресации)      [используется в сложной адресации]
    "рсиай": 6,  # RSI - индекс источника                                           [используется в сложной адресации]
    "рдиай": 7,  # RDI - индекс назначения                                          [используется в сложной адресации]
    "р8"   : 8,  # R8                                                               [используется в сложной адресации]
    "р9"   : 9,  # R9                                                               [используется в сложной адресации]    
    "р10"  : 10, # R10                                                              [используется в сложной адресации]
    "р11"  : 11, # R11                                                              [используется в сложной адресации]
    "р12"  : 12, # R12                                                              [используется в сложной адресации]
    "р13"  : 13, # R13                                                              [используется в сложной адресации]
    "р14"  : 14, # R14                                                              [используется в сложной адресации]
    "р15"  : 15, # R15                                                              [используется в сложной адресации]

    # Младшие 32-битные части (EAX, ECX и т.д.)
    "еаикс": 0,  # EAX - аккумуляторный регистр
    "есикс": 1,  # ECX - счетный регистр
    "едикс": 2,  # EDX - регистр данных
    "ебикс": 3,  # EBX - базовый регистр
    "есипи": 4,  # ESP - указатель стека    (используется в стековой адресации)
    "ебипи": 5,  # EBP - базовый указатель  (используется в базовой адресации)
    "есиай": 6,  # ESI - индекс источника
    "едиай": 7,  # EDI - индекс назначения
    "р8д"  : 8,  # R8D
    "р9д"  : 9,  # R9D
    "р10д" : 10, # R10D
    "р11д" : 11, # R11D
    "р12д" : 12, # R12D
    "р13д" : 13, # R13D
    "р14д" : 14, # R14D
    "р15д" : 15, # R15D

    # Младшие 16-битные части
    "аикс": 0,   # AX  - аккумуляторный регистр
    "сикс": 1,   # CX  - счетный регистр
    "дикс": 2,   # DX  - регистр данных
    "бикс": 3,   # BX  - базовый регистр
    "эсп" : 4,   # SP  - указатель стека     (используется в стековой адресации)
    "бипи": 5,   # BP  - базовый указатель   (используется в базовой адресации)
    "эс"  : 6,   # SI  - индекс источника
    "ди"  : 7,   # DI  - индекс назначения
    "р8в" : 8,   # R8W
    "р9в" : 9,   # R9W
    "р10в": 10,  # R10W
    "р11в": 11,  # R11W
    "р12в": 12,  # R12W
    "р13в": 13,  # R13W
    "р14в": 14,  # R14W
    "р15в": 15,  # R15W

    # Младшие 8-битные части     (могут использоваться в адресации, но реже)
    "ал"  : 0,   # AL  - младший байт аккумулятора
    "кл"  : 1,   # CL  - младший байт счетчика
    "дл"  : 2,   # DL  - младший байт данных
    "бл"  : 3,   # BL  - младший байт базы
    "спл" : 4,   # SPL - младший байт указателя стека    (младшие 8 бит RSP)
    "бпл" : 5,   # BPL - младший байт базового указателя (младшие 8 бит RBP)
    "сил" : 6,   # SIL - младший байт индекса источника  (младшие 8 бит RSI)
    "дил" : 7,   # DIL - младший байт индекса назначения (младшие 8 бит RDI)
    "р8б" : 8,   # R8B
    "р9б" : 9,   # R9B
    "р10б": 10,  # R10B
    "р11б": 11,  # R11B
    "р12б": 12,  # R12B
    "р13б": 13,  # R13B
    "р14б": 14,  # R14B
    "р15б": 15,  # R15B

    # Старшие 8-битные части        (не могут использоваться в большинстве режимов адресации)
    "аш"  : 0,   # AH - старший байт аккумулятора   (нельзя использовать в сложной адресации)
    "чш"  : 1,   # CH - старший байт счетчика       (нельзя использовать в сложной адресации)
    "дш"  : 2,   # DH - старший байт данных         (нельзя использовать в сложной адресации)
    "бш"  : 3,   # BH - старший байт базы           (нельзя использовать в сложной адресации)
}

# Глобальное состояние ассемблера
labels          = {}
label_sections  = {}
symbols         = {}
sections        = {".text": bytearray(), ".data": bytearray(), ".comment": bytearray()}
current_section = ".text"
entry_point     = "_start"
position        = {".text": 0, ".data": 0, ".comment": 0}
pass_num        = 0
log_entries     = []

# === ELF layout ===
PAGE_SIZE       = 0x1000
elf_base_vaddr  = 0x400000
text_vaddr_base = 0x401000
data_vaddr_base = 0x402000

text_size       = 0
data_size       = 0
comment_size    = 0
offset_text     = 0
offset_data     = 0
offset_comment  = 0
shstrtab_offset = 0
shdr_offset     = 0
vaddr_text      = 0
vaddr_data      = 0

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

# === Функции ошибок ===
def make_error_msg(line_num, line_text, detail):
    return "Ошибка в файле " + source_filename + ", строка " + str(line_num) + ":\n    " + line_text + "\n" + detail

def error_invalid_operand_count(mnemonic, expected, got):
    return "Инструкция '" + mnemonic + "':\n    ожидается " + str(expected) + " операнд(а/ов), получено: " + str(got)

def error_unknown_mnemonic(mnemonic):
    return "Неизвестная инструкция: '" + mnemonic + "'"

def error_invalid_register(op_name, reg_name, mnemonic):
    return ("Инструкция '" + mnemonic + "':\n    операнд '" + op_name + "' = '" + reg_name +
            "' не является допустимым регистром.\n    Допустимые регистры: " + ", ".join(list(REGISTERS.keys())))

def error_expected_register(op_name, value, mnemonic):
    return ("Инструкция '" + mnemonic + "':\n    операнд '" + op_name + "' = '" + value + "' должен быть регистром.")

def error_invalid_number_format(s):
    return "Недопустимый формат числа: '" + s + "'"

def error_byte_out_of_range(val_str, val):
    return "Байт должен быть в диапазоне 0–255: '" + val_str + "' = " + str(val)

def error_unknown_directive(word):
    return "Неизвестная директива: '" + word + "'"

def error_missing_label(label):
    return "Метка не найдена: '" + label + "'"

def error_unexpected_string_in_byte():
    return ".байт требует числовые значения, не строки"

def error_unterminated_string():
    return "Незакрытая кавычка в строке"

def error_invalid_address_operand(addr_op):
    return "Первый операнд должен быть [регистр], получено: " + addr_op

def error_unexpected_token_in_operands(tok):
    return "Недопустимый токен в операндах: " + str(tok)

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

# === Парсинг операндов ===
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
            return 0  # На первом проходе адрес не важен
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


# === Генерация инструкций ===
def encode_instruction(mnemonic, operands, line_num, line_text):
    instr = INSTRUCTIONS[mnemonic]
    code = bytearray()
    itype = instr["type"]

    if itype == "none":
        code.extend(instr["code"])

    # СТАНДАРТНЫЕ ИНСТРУКЦИИ    

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

        use_rex_w = (dst_size == 64)
        use_66_prefix = (dst_size == 16)

        rex = 0x40
        if use_rex_w:
            rex |= 0x08
        if src >= 8:
            rex |= 0x04
        if dst >= 8:
            rex |= 0x01

        if dst_info.get("high8") or src_info.get("high8"):
            if rex != 0x40:
                raise ValueError("Нельзя использовать старшие байты с расширенными регистрами")
            rex = 0

        op_base = instr["code"]
        if op_base[0] == 0x48 and len(op_base) == 2:
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
                code.extend(struct.pack('<Q', imm & 0xFFFFFFFFFFFFFFFF))
            elif 8 <= reg <= 15:
                code.extend(b'\x49')
                code.append(0xB8 + (reg - 8))
                code.extend(struct.pack('<Q', imm & 0xFFFFFFFFFFFFFFFF))
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
                code.extend(struct.pack('<H', imm & 0xFFFF))
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

    elif itype == "call" or itype == "jmp":
        if len(operands) != 1:
            raise ValueError(error_invalid_operand_count(mnemonic, 1, len(operands)))
        code.extend(instr["code"])
        target = parse_operand(operands[0])
        current_addr = vaddr_text + position[".text"]
        offset = target - (current_addr + 5)
        if offset < -0x80000000 or offset > 0x7FFFFFFF:
            raise ValueError("Цель слишком далеко для 32-битного смещения: " + str(offset))
        code.extend(struct.pack('<i', offset))

    elif itype == "jcc":
        if len(operands) != 1:
            raise ValueError(error_invalid_operand_count(mnemonic, 1, len(operands)))
        code.extend(instr["code"])
        target = parse_operand(operands[0])
        current_addr = vaddr_text + position[".text"]
        offset = target - (current_addr + 6)
        if offset < -0x80000000 or offset > 0x7FFFFFFF:
            raise ValueError("Цель слишком далеко: " + str(offset))
        code.extend(struct.pack('<i', offset))

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
            raise ValueError("Недопустимый регистр")

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
        elif size == 32:
            rex = 0x40
            if reg >= 8:
                rex |= 0x01
            if rex != 0x40:
                code.append(rex)
            code.append(0xF7)
        elif size == 16:
            code.append(0x66)
            rex = 0x40
            if reg >= 8:
                rex |= 0x01
            if rex != 0x40:
                code.append(rex)
            code.append(0xF7)
        elif size == 8:
            if reg_info.get("high8"):
                if reg < 4:
                    code.append(0xF6)
                else:
                    raise ValueError("Старшие байты только для первых 4 регистров")
            else:
                if reg < 4:
                    code.append(0xF6)
                else:
                    rex = 0x40
                    if reg >= 8:
                        rex |= 0x01
                    code.append(rex)
                    code.append(0xF6)
        else:
            raise ValueError("Неподдерживаемый размер регистра")
        modrm = 0xC0 | (subop << 3) | (reg & 7)
        code.append(modrm)

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
            raise ValueError("LEA поддерживает только 64-битные регистры")
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
        code.extend(struct.pack('<i', disp))

    elif itype in ("shift_imm", "rotate_imm"):
        if len(operands) != 2:
            raise ValueError(error_invalid_operand_count(mnemonic, 2, len(operands)))
        reg_info = get_reg_info(operands[0])
        if reg_info is None:
            raise ValueError(error_invalid_register("регистра", operands[0], mnemonic))
        imm = parse_operand(operands[1])
        if not (0 <= imm <= 255):
            raise ValueError("Сдвиг/вращение должно быть в диапазоне 0–255")
        reg = reg_info["index"]
        size = reg_info["size"]
        base_op = instr["code"][-1]

        if size == 64:
            rex = 0x48
            if reg >= 8:
                rex |= 0x01
            code.append(rex)
            code.append(0xC1)
        elif size == 32:
            rex = 0x40
            if reg >= 8:
                rex |= 0x01
            if rex != 0x40:
                code.append(rex)
            code.append(0xC1)
        elif size == 16:
            code.append(0x66)
            rex = 0x40
            if reg >= 8:
                rex |= 0x01
            if rex != 0x40:
                code.append(rex)
            code.append(0xC1)
        elif size == 8:
            if reg_info.get("high8"):
                if reg < 4:
                    code.append(0xC0)
                else:
                    raise ValueError("Старшие байты только для первых 4 регистров")
            else:
                if reg < 4:
                    code.append(0xC0)
                else:
                    rex = 0x40
                    if reg >= 8:
                        rex |= 0x01
                    code.append(rex)
                    code.append(0xC0)
        else:
            raise ValueError("Неподдерживаемый размер регистра")
        modrm = 0xC0 | (base_op << 3) | (reg & 7)
        code.append(modrm)
        code.append(imm & 0xFF)

    elif itype == "int":
        if len(operands) != 1:
            raise ValueError(error_invalid_operand_count(mnemonic, 1, len(operands)))
        imm = parse_operand(operands[0])
        if not (0 <= imm <= 255):
            raise ValueError("Номер прерывания должен быть 0–255")
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
            raise ValueError("Назначение должно быть 64-битным")
        if src_info["size"] not in (8, 16):
            raise ValueError("Источник должен быть 8- или 16-битным")

        rex = 0x48
        if src >= 8:
            rex |= 0x04
        if dst >= 8:
            rex |= 0x01
        code.append(rex)
        code.extend(instr["code"][1:])
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
            raise ValueError("Размеры операндов не совпадают")

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
            raise ValueError("Операнды должны быть 8-битными")
        dst = dst_info["index"]
        src = src_info["index"]

        op_map = {"add_reg8_reg8": 0x00, "sub_reg8_reg8": 0x28, "cmp_reg8_reg8": 0x38}
        op = op_map[itype]

        if dst_info.get("high8") or src_info.get("high8"):
            if dst >= 4 or src >= 4:
                raise ValueError("Старшие байты только для первых 4 регистров")
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
                raise ValueError("Непосредственное значение слишком велико: " + str(imm))
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
                raise ValueError("32-битное значение вне диапазона")
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
                code.extend(struct.pack('<H', imm & 0xFFFF))
            else:
                raise ValueError("16-битное значение вне диапазона")
        elif size == 8:
            if not (0 <= imm <= 255):
                raise ValueError("8-битное значение вне диапазона")
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
            raise ValueError("Операнды должны быть 32-битными")
        dst = dst_info["index"]
        src = src_info["index"]

        op_map = {"mov32_reg_reg": 0x89, "add32_reg_reg": 0x01, "sub32_reg_reg": 0x29, "cmp32_reg_reg": 0x39}
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
                modrm = (0xC0 if is_add else 0xE8) | (reg & 7)
                code.append(modrm)
                code.append(imm & 0xFF)
            elif -0x80000000 <= imm <= 0x7FFFFFFF:
                rex = 0x48
                if reg >= 8:
                    rex |= 0x01
                code.append(rex)
                code.append(0x81)
                modrm = (0xC0 if is_add else 0xE8) | (reg & 7)
                code.append(modrm)
                code.extend(struct.pack('<I', imm & 0xFFFFFFFF))
            else:
                raise ValueError("Непосредственное значение слишком велико")
        elif size == 32:
            if -128 <= imm <= 127:
                rex = 0x40
                if reg >= 8:
                    rex |= 0x01
                if rex != 0x40:
                    code.append(rex)
                code.append(0x83)
                modrm = (0xC0 if is_add else 0xE8) | (reg & 7)
                code.append(modrm)
                code.append(imm & 0xFF)
            elif -0x80000000 <= imm <= 0x7FFFFFFF:
                rex = 0x40
                if reg >= 8:
                    rex |= 0x01
                if rex != 0x40:
                    code.append(rex)
                code.append(0x81)
                modrm = (0xC0 if is_add else 0xE8) | (reg & 7)
                code.append(modrm)
                code.extend(struct.pack('<I', imm & 0xFFFFFFFF))
            else:
                raise ValueError("32-битное значение вне диапазона")
        elif size == 16:
            if -128 <= imm <= 127:
                code.append(0x66)
                rex = 0x40
                if reg >= 8:
                    rex |= 0x01
                if rex != 0x40:
                    code.append(rex)
                code.append(0x83)
                modrm = (0xC0 if is_add else 0xE8) | (reg & 7)
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
                modrm = (0xC0 if is_add else 0xE8) | (reg & 7)
                code.append(modrm)
                code.extend(struct.pack('<H', imm & 0xFFFF))
            else:
                raise ValueError("16-битное значение вне диапазона")
        elif size == 8:
            if not (0 <= imm <= 255):
                raise ValueError("8-битное значение вне диапазона")
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

    elif itype in ("in_imm", "out_imm"):
        if len(operands) != 1:
            raise ValueError(error_invalid_operand_count(mnemonic, 1, len(operands)))
        imm = parse_operand(operands[0])
        if not (0 <= imm <= 255):
            raise ValueError("Порт должен быть 0–255")
        code.append(instr["code"][0])
        code.append(imm & 0xFF)

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


    # ГРУППА ИНСТРУКЦИЙ С ПОДДЕРЖКОЙ СЛОЖНОЙ АДРЕСАЦИИ

    elif itype in ("mov_mem8_reg8", "store_reg8_to_reg64"):         # [МОЖНО ВНЕДРИТЬ СЛОЖНУЮ АДРЕСАЦИЮ]
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

    elif itype in ("mov_reg_mem", "mov_mem_reg", "xchg_mem_reg"):   # [МОЖНО ВНЕДРИТЬ СЛОЖНУЮ АДРЕСАЦИЮ]
        if len(operands) != 2:
            raise ValueError(error_invalid_operand_count(mnemonic, 2, len(operands)))
        if itype in ("mov_reg_mem", "xchg_mem_reg"):
            dst_info = get_reg_info(operands[0])
            src_op = operands[1]
            is_load = True
        else:
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

        op_map = {"mov_reg_mem": (0x8B, True), "mov_mem_reg": (0x89, False), "xchg_mem_reg": (0x87, False)}
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
                raise ValueError("Загрузка 8-битного регистра из памяти не поддерживается")
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

    elif itype in ("push_mem", "pop_mem"):                          # [МОЖНО ВНЕДРИТЬ СЛОЖНУЮ АДРЕСАЦИЮ]
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

        rex = 0x40
        if base >= 8:
            rex |= 0x01
        op = 0xFF if itype == "push_mem" else 0x8F
        subop = 6 if itype == "push_mem" else 0

        if base == 4 or base == 12:  # rsp/r12
            if rex != 0x40:
                code.append(rex)
            code.append(op)
            code.append(0x24)
            code.append(0x24)
        elif base == 5 or base == 13:  # rbp/r13
            if rex != 0x40:
                code.append(rex)
            code.append(op)
            code.append(0x40 | (subop << 3) | (base & 7))
            code.append(0x00)
        else:
            if rex != 0x40:
                code.append(rex)
            code.append(op)
            modrm = (subop << 3) | (base & 7)
            code.append(modrm)

    elif itype == "mov_reg8_mem":                                   # [МОЖНО ВНЕДРИТЬ СЛОЖНУЮ АДРЕСАЦИЮ]
        if len(operands) != 2:
            raise ValueError(error_invalid_operand_count(mnemonic, 2, len(operands)))
        dst_info = get_reg_info(operands[0])
        src_op = operands[1]
        
        if not (src_op.startswith('[') and src_op.endswith(']')):
            raise ValueError(error_invalid_address_operand(src_op))
        
        base_name = src_op[1:-1]
        base_info = get_reg_info(base_name)
        if base_info is None:
            raise ValueError(error_invalid_register("адресного регистра", base_name, mnemonic))
        if dst_info is None:
            raise ValueError(error_invalid_register("назначения", operands[0], mnemonic))
        if base_info["size"] != 64:
            raise ValueError("Адресный регистр должен быть 64-битным")
        if dst_info["size"] != 8:
            raise ValueError("Назначение должно быть 8-битным")

        dst = dst_info["index"]
        base = base_info["index"]

        if dst_info.get("high8"):
            if dst >= 4:
                raise ValueError("Старшие байты только для первых 4 регистров")
            code.append(0x8A)
            modrm = 0x00 | (dst << 3) | base
            code.append(modrm)
        else:
            rex = 0x40
            if dst >= 8:
                rex |= 0x01
            if base >= 8:
                rex |= 0x01
            if rex != 0x40:
                code.append(rex)
            code.append(0x8A)
            modrm = 0x00 | ((dst & 7) << 3) | (base & 7)
            code.append(modrm)

    elif itype == "cmp_mem8_imm":                                   # [МОЖНО ВНЕДРИТЬ СЛОЖНУЮ АДРЕСАЦИЮ]
        if len(operands) != 2:
            raise ValueError(error_invalid_operand_count(mnemonic, 2, len(operands)))
        addr_op = operands[0]
        imm = parse_operand(operands[1])
        
        if not (addr_op.startswith('[') and addr_op.endswith(']')):
            raise ValueError(error_invalid_address_operand(addr_op))
        
        base_name = addr_op[1:-1]
        base_info = get_reg_info(base_name)
        if base_info is None:
            raise ValueError(error_invalid_register("адресного регистра", base_name, mnemonic))
        if base_info["size"] != 64:
            raise ValueError("Адресный регистр должен быть 64-битным")

        base = base_info["index"]
        subop = instr["subop"]

        rex = 0x40
        if base >= 8:
            rex |= 0x01
        if rex != 0x40:
            code.append(rex)
        code.append(0x80)
        modrm = 0x00 | (subop << 3) | (base & 7)
        code.append(modrm)
        code.append(imm & 0xFF)

    else:
        raise ValueError("Неизвестный тип инструкции: " + itype)

    #print(f"DEBUG: {mnemonic} -> {[hex(b) for b in code]}")
    return bytes(code)


# === Разбор директив и инструкций ===
def parse_instruction_or_directive(tokens, line_num, line_text):
    global current_section, entry_point, symbols
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
        elif word == '.константа':
            if len(tokens) < 3 or tokens[1][0] != 'word' or tokens[2][0] != 'word' or tokens[2][1] != '=' or len(tokens) < 4:
                raise ValueError(".константа требует формат: .константа <имя> = <значение>")
            const_name = tokens[1][1]
            const_value = parse_number_token(tokens[3])
            symbols[const_name] = const_value
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
                    elif op_str in symbols:
                        target_addr = hex(symbols[op_str])
            except Exception:
                target_addr = "ошибка"

            original_cmd = line_text.split(';')[0].strip()
            for i, byte in enumerate(code):
                addr       = start_vaddr + i
                byte_hex   = "{:02X}".format(byte)
                cmd_to_log = original_cmd if i == 0 else ""
                log_entries.append((hex(addr), byte_hex, target_addr if i == 0 else "", cmd_to_log))

        sections[current_section] += code
        position[current_section] += len(code)
    else:
        instr_info = INSTRUCTIONS[mnemonic]
        itype = instr_info["type"]
        size_map = {
            "reg_imm"               : 10,
            "reg_reg"               : 3,
            "test"                  : 3,
            "call"                  : 5,
            "jmp"                   : 5,
            "jcc"                   : 6,
            "push"                  : 1,
            "pop"                   : 1,
            "none"                  : lambda: len(instr_info["code"]),
            "incdec"                : 3,
            "unary"                 : 3,
            "muldiv"                : 3,
            "shift_imm"             : 4,
            "rotate_imm"            : 4,
            "int"                   : 2,
            "lea"                   : 7,
            "movzx"                 : 4,
            "movsx"                 : 4,
            "xchg"                  : 3,
            "loop"                  : 2,
            "mov_reg8_imm8"         : 3,
            "add_reg8_reg8"         : 3,
            "mov_mem8_reg8"         : 3,
            "store_reg8_to_reg64"   : 3,

            "cmp_reg_imm"           : 7,    # REX  + 0x81 + ModR/M + imm32
            "mov_reg_mem"           : 3,    # REX  + 0x8B + ModR/M
            "mov_mem_reg"           : 3,    # REX  + 0x89 + ModR/M
            "xchg_mem_reg"          : 3,    # REX  + 0x87 + ModR/M
            "mov32_reg_reg"         : 3,    # REX  + 0x89 + ModR/M
            "add32_reg_reg"         : 3,    # REX  + 0x01 + ModR/M
            "sub32_reg_reg"         : 3,    # REX  + 0x29 + ModR/M
            "cmp32_reg_reg"         : 3,    # REX  + 0x39 + ModR/M
            "sub_reg8_reg8"         : 3,    # REX  + 0x28 + ModR/M
            "cmp_reg8_reg8"         : 3,    # REX  + 0x38 + ModR/M
            "add_reg_imm"           : 7,    # REX  + 0x81 + ModR/M + imm32
            "sub_reg_imm"           : 7,    # REX  + 0x81 + ModR/M + imm32
            "xor_self"              : 3,    # REX  + 0x31 + ModR/M
            "push_mem"              : 4,    # REX  + 0xFF + ModR/M (/6) (тестировать корректность байтогенерации (SIB))
            "pop_mem"               : 4,    # REX  + 0x8F + ModR/M (/0) (тестировать корректность байтогенерации (SIB))
            "in_imm"                : 2,    # 0xE4 + imm8
            "out_imm"               : 2,    # 0xE6 + imm8
            "short_jmp"             : 2,    # 0xEB + disp8
            "short_jcc"             : 2,
            "mov_reg8_mem"          : 3,    # REX  + 0x8A + ModR/M
            "cmp_mem8_imm"          : 4,    # REX  + 0x80 + ModR/M + imm8
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
    symbols.clear()

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

    # РАЗМЕЩЕНИЕ (как в kvs_8)
    elf_header_size  = 64
    ph_size          = 56
    ph_num           = 3
    ph_table_size    = ph_num * ph_size

    offset_text      = align_up(elf_header_size + ph_table_size, PAGE_SIZE)
    offset_data      = align_up(offset_text + text_size_pass1, PAGE_SIZE)
    vaddr_text       = text_vaddr_base
    vaddr_data       = align_up(vaddr_text + text_size_pass1, PAGE_SIZE)

    comment_content  = "Сборщик КВС".encode('utf-8') + b'\x00'
    comment_size     = len(comment_content)
    offset_comment   = align_up(offset_data + data_size_pass1, 1)

    shstrtab_content = b"\x00.text\x00.data\x00.comment\x00.shstrtab\x00"
    shstrtab_size    = len(shstrtab_content)
    shstrtab_offset  = align_up(offset_comment + comment_size, 8)
    shdr_size        = 64
    shdr_num         = 5
    shdr_offset      = align_up(shstrtab_offset + shstrtab_size, 16)

    print("РАЗМЕЩЕНИЕ: .text at offset=" + hex(offset_text) + ", .data at offset=" + hex(offset_data))
    print("ВИРТУАЛЬНЫЕ АДРЕСА: .text at " + hex(vaddr_text) + ", .data at " + hex(vaddr_data))

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
        print("ПРЕДУПРЕЖДЕНИЕ: Размер .text изменился: " + str(text_size_pass1) + " -> " + str(text_size_pass2))
    if data_size_pass1 != data_size_pass2:
        print("ПРЕДУПРЕЖДЕНИЕ: Размер .data изменился: " + str(data_size_pass1) + " -> " + str(data_size_pass2))

    text_size = text_size_pass2
    data_size = data_size_pass2

def create_elf(filename):
    global sections, entry_point, labels, vaddr_text, vaddr_data
    global offset_text, offset_data, offset_comment, shstrtab_offset, shdr_offset

    text    = sections[".text"]
    data    = sections[".data"]
    comment = sections[".comment"]

    actual_text_size    = len(text)
    actual_data_size    = len(data)
    expected_vaddr_data = align_up(vaddr_text + actual_text_size, PAGE_SIZE)
    if vaddr_data != expected_vaddr_data:
        print("КОРРЕКЦИЯ: vaddr_data исправлен с " + hex(vaddr_data) + " на " + hex(expected_vaddr_data))
        vaddr_data = expected_vaddr_data

    print("ФАКТИЧЕСКИЕ РАЗМЕРЫ: .text=" + str(actual_text_size) + ", .data=" + str(actual_data_size))
    print("КОНЕЧНЫЕ АДРЕСА: .text ends at " + hex(vaddr_text + actual_text_size) + ", .data starts at " + hex(vaddr_data))

    entry_addr = vaddr_text + labels.get(entry_point, 0)

    shstrtab_content = b"\x00.text\x00.data\x00.comment\x00.shstrtab\x00"
    shstrtab_size    = len(shstrtab_content)

    elf_header_size = 64
    ph_size         = 56
    ph_num          = 3
    shdr_size       = 64
    shdr_num        = 5

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

    sh0 = shdr(0,  0, 0, 0, 0, 0)
    sh1 = shdr(1,  1, 6, vaddr_text, offset_text, len(text), 16)
    sh2 = shdr(7,  1, 3, vaddr_data, offset_data, len(data), 8)
    sh3 = shdr(13, 1, 0, 0, offset_comment, len(comment), 1)
    sh4 = shdr(22, 3, 0, 0, shstrtab_offset, shstrtab_size, 1)

    shdrs = sh0 + sh1 + sh2 + sh3 + sh4
    elf_data[shdr_offset : shdr_offset + len(shdrs)] = shdrs

    f_out = open(filename, "wb")
    f_out.write(elf_data)
    f_out.close()

    os.chmod(filename, 0o755)



# == РЕАЛИЗАЦИЯ ИМПОРТА ==
# добавить поиск модулей по абсолютным и относительным путям,
# команда .путь_импорта



def build_intermediate(main_file: str) -> str:
    """
    Собирает промежуточный текст со всеми импортами и переименованными метками/данными.
    Возвращает ПОЛНЫЙ текст промежуточного файла (str).
    """
    visited    = set()     # абсолютные пути уже обработанных файлов
    data_lines = []        # итоговая секция .данные
    text_lines = []        # итоговая секция .текст

    # нормализованное имя метки:  метка + суффикс модуля
    def qual(label: str, module: str) -> str:
        return f"{label}_{module}"

    def rename_line(line: str, module: str, labels: set, constants: set) -> str:
        """Улучшенная функция переименования с обработкой констант и глобальных меток"""
        if not line.strip():
            return line
            
        # Обработка директивы .глобал
        if line.strip().startswith('.глобал'):
            parts = line.split()
            if len(parts) >= 2:
                global_label = parts[1]
                if global_label in labels:
                    return f".глобал {qual(global_label, module)}"
        
        # Обработка директивы .константа
        elif line.strip().startswith('.константа'):
            parts = line.split('=', 1)
            if len(parts) >= 2:
                const_part  = parts[0].strip()
                value_part  = parts[1].strip()
                const_parts = const_part.split()
                if len(const_parts) >= 2:
                    const_name = const_parts[1]
                    if const_name in constants:
                        new_const_name = qual(const_name, module)
                        # Переименовываем также использование этой константы в значении
                        new_value = value_part
                        for const in constants:
                            new_value = new_value.replace(const, qual(const, module))
                        for lbl in labels:
                            new_value = new_value.replace(lbl, qual(lbl, module))
                        return f".константа {new_const_name} = {new_value}"
        
        # Общая замена для всех остальных случаев
        result = line
        for const in sorted(constants, key=len, reverse=True):
            result = result.replace(const, qual(const, module))
        for lbl in sorted(labels, key=len, reverse=True):
            result = result.replace(lbl, qual(lbl, module))
        return result

    def process(path: str):
        abspath = os.path.abspath(path)
        if abspath in visited:
            return
        visited.add(abspath)

        module_name = os.path.splitext(os.path.basename(path))[0]
        with open(path, encoding="utf-8") as f:
            src = f.read()

        # 1-й проход — собираем метки И константы
        labels = set()
        constants = set()
        for line in src.splitlines():
            line = line.split(';')[0].rstrip()
            
            # Собираем метки
            if ':' in line:
                lbl = line.split(':')[0].strip()
                if lbl and not lbl.startswith('.'):
                    labels.add(lbl)
            
            # Собираем константы
            if line.startswith('.константа'):
                parts = line.split()
                if len(parts) >= 2:
                    # Берем имя константы (часть до = если есть)
                    const_name = parts[1].split('=')[0].strip()
                    constants.add(const_name)

        # 2-й проход — раскидываем строки и переименовываем
        cur_data = False
        cur_text = False
        for raw in src.splitlines(True):        # splitlines(True) сохраняет \n
            line = raw.rstrip()
            if line.startswith('.данные'):
                cur_data, cur_text = True, False
                continue
            if line.startswith('.текст'):
                cur_data, cur_text = False, True
                continue
            if line.startswith('.импорт'):
                parts = line.split()
                if len(parts) != 2:
                    raise ValueError(f"Неверная директива импорта: {line}")
                nextfile = parts[1]
                if not nextfile.endswith('.квс'):
                    nextfile += '.квс'
                # ищем рядом с текущим файлом
                neighbour = os.path.join(os.path.dirname(abspath), nextfile)
                process(neighbour)
                continue

            new_line = rename_line(raw, module_name, labels, constants)
            if cur_data:
                data_lines.append(new_line)
            else:
                text_lines.append(new_line)

    # стартуем рекурсию из главного файла
    process(main_file)

    # склеиваем финальный текст
    intermediate = ['.данные', *data_lines, '.текст', *text_lines]
    return '\n'.join(intermediate)


# == РЕАЛИЗАЦИЯ СЛОЖНОЙ АДРЕСАЦИИ == 

"""
-раскрутить сложную адресацию в несколько простых инструкций
-создать промежуточный файл ,где вся сложная адресация превращена в простые инструкции
-делать сборку из промежуточного файла


Преимущества подхода с промежуточным файлом:
    -Разделение ответственности - парсинг и кодогенерация разделены
    -Простота отладки - можно посмотреть промежуточный код
    -Меньше багов - не нужно усложнять основной ассемблер
    -Гибкость - можно легко добавлять новые паттерны трансформации
    -Совместимость - не ломает существующий рабочий код

Конкретная архитектура:
    -Парсинг исходника → токены и AST
    -Трансформация → замена сложных конструкций простыми
    -Генерация промежуточного файла (.квс.промежуточный)
    -Ассемблирование промежуточного файла → машинный код
    -Генерация ELF
"""


# === Главная функция ===
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Использование: python kvs_9_8.py <файл.квс>")
        sys.exit(1)

    source_file = sys.argv[1]
    source_filename = source_file
    if not source_file.endswith('.квс'):
        print("Ошибка: файл должен иметь расширение .квс")
        sys.exit(1)

    # читаем исходник только для построения промежуточного
    try:
        with open(source_file, encoding="utf-8") as f:
            f.read()          # проверка существования/кодировки
    except FileNotFoundError:
        print("Ошибка: файл '" + source_file + "' не найден.")
        sys.exit(1)
    except UnicodeDecodeError as e:
        print("Ошибка кодировки в файле '" + source_file + "': " + str(e))
        sys.exit(1)

    intermediate_text = build_intermediate(source_file)
    int_file = source_file + ".промежуточный"
    with open(int_file, "w", encoding="utf-8") as f:
        f.write(intermediate_text)
    print("Промежуточный файл создан:", int_file)

    try:
        parse(intermediate_text)        
        elf_file = source_file[:-4] + ".elf"
        create_elf(elf_file)

        log_file = source_file[:-4] + ".log.csv"
        with open(log_file, "w", encoding="utf-8") as f_log:
            f_log.write("адрес;байт;целевой_адрес;исходная_команда\n")
            for addr, byte, target, cmd in log_entries:
                if cmd and ('"' in cmd or ';' in cmd):
                    cmd = '"' + cmd.replace('"', '""') + '"'
                f_log.write(f"{addr};{byte};{target};{cmd}\n")
        print("Лог создан:", log_file)

        print("ELF-файл создан:", elf_file)
        print("Запустить: ./" + elf_file)
    except SystemExit:
        raise
    except Exception as e:
        print("Внутренняя ошибка ассемблера: " + str(e), file=sys.stderr)
        sys.exit(1)