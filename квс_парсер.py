#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Парсер КВС (адаптирован под русские токены)
Принимает: файл токенов от лексера (русские названия типов)
Выдаёт: текстовый файл с AST-структурой

Поддерживает сложную адресацию:
- [регистр + регистр*масштаб + смещение]
"""

import sys
sys.path.insert(0, '.')
from kvs_data import REGISTERS, INSTRUCTIONS


def make_memory_operand(addr_type, base_reg=None, displacement=None, label=None):
    """Создаёт кортеж операнда памяти.
    Формат: (addr_type, base_reg, displacement, label)
    """
    return (addr_type, base_reg, displacement, label)


def memory_operand_to_ast_string(mem_op):
    """Преобразует кортеж памяти в строку AST.
    Формат: 'MEM:тип:данные'
    """
    addr_type = mem_op[0]
    if addr_type == 'absolute':
        if mem_op[3] is not None:  # label
            return f"MEM:absolute:{mem_op[3]}"
        else:  # displacement
            return f"MEM:absolute:{mem_op[2]}"
    elif addr_type == 'register_indirect':
        return f"MEM:reg_indirect:{mem_op[1]}"
    elif addr_type == 'complex':
        return f"MEM:complex:{mem_op[1]}+{mem_op[2]}*{mem_op[3]}+{mem_op[4]}"
    else:
        return f"MEM:unknown"


def read_tokens(input_file):
    """Читает токены из файла (русские названия типов)"""
    tokens = []
    with open(input_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            colon_pos = line.find(':')
            if colon_pos == -1:
                continue
            tok_type = line[:colon_pos]
            tok_value = line[colon_pos + 1:]
            tokens.append((tok_type, tok_value))
    return tokens


# ==================== СОСТОЯНИЕ ПАРСЕРА ====================
# Хранится в словаре, передаётся во все функции явно

def parser_init(tokens):
    """Создаёт начальное состояние парсера"""
    return {
        'tokens': tokens,
        'pos': 0,
        'current_section': '.text',
        'parsed_lines': []
    }


def parser_peek(state):
    """Подсмотреть текущий токен"""
    if state['pos'] < len(state['tokens']):
        return state['tokens'][state['pos']]
    return None


def parser_next_token(state):
    """Взять текущий токен и продвинуться"""
    tok = parser_peek(state)
    if tok:
        state['pos'] += 1
    return tok


def parser_expect(state, expected_type):
    """Ожидать токен определённого типа"""
    tok = parser_next_token(state)
    if tok is None or tok[0] != expected_type:
        raise ValueError(f"Ожидался {expected_type}, получено {tok}")
    return tok


def parser_expect_one_of(state, expected_types):
    """Ожидает один из нескольких типов токенов"""
    tok = parser_peek(state)
    if tok is None or tok[0] not in expected_types:
        raise ValueError(f"Ожидался один из {expected_types}, получено {tok}")
    return parser_next_token(state)


# ==================== РАЗБОР ОПЕРАНДОВ ====================

def parse_operand(state):
    """Разбирает один операнд"""
    tok = parser_peek(state)
    if tok is None:
        return None

    if tok[0] == 'СК_ОТКР':
        parser_next_token(state)
        return parse_memory_operand(state)
    elif tok[0] == 'ЧИСЛО':
        return parser_next_token(state)[1]
    elif tok[0] == 'СТРОКА':
        return parser_next_token(state)[1]
    elif tok[0] == 'СЛОВО':
        return parser_next_token(state)[1]
    else:
        raise ValueError(f"Неожиданный токен в операнде: {tok}")


def parse_memory_operand(state):
    """Разбирает операнд памяти"""
    parts = []

    while True:
        tok = parser_peek(state)
        if tok is None:
            raise ValueError("Незакрытая квадратная скобка")

        if tok[0] == 'СК_ЗАКР':
            parser_next_token(state)
            break

        if tok[0] in ('СЛОВО', 'ЧИСЛО', 'ПЛЮС', 'МИНУС', 'ЗВЕЗДА'):
            parts.append(parser_next_token(state)[1])
        else:
            raise ValueError(f"Неожиданный токен в адресации: {tok}")

    if len(parts) == 1:
        part = parts[0]
        if part in REGISTERS:
            return make_memory_operand('register_indirect', base_reg=part)

    expr = ' '.join(parts)
    return f"[{expr}]"


# ==================== РАЗБОР ДИРЕКТИВ ====================

def parse_directive(state, word):
    """
    Разбор директив ассемблера.
    Вызывает ошибку при некорректном синтаксисе или контексте.
    """
    # === Секции ===
    if word == '.текст':
        state['current_section'] = ".text"
        state['parsed_lines'].append(f"DIRECTIVE:{word}")

    elif word == '.данные':
        state['current_section'] = ".data"
        state['parsed_lines'].append(f"DIRECTIVE:{word}")

    elif word == '.бнд':
        state['current_section'] = ".бнд"
        state['parsed_lines'].append(f"DIRECTIVE:{word}")

    # === Глобальные метки ===
    elif word == '.глобал':
        label = parser_expect(state, 'СЛОВО')[1]
        state['parsed_lines'].append(f"DIRECTIVE:{word}:{label}")

    # === Строковые директивы (запрещены в .бнд) ===
    elif word in ('.строка_нуль', '.строка'):
        if state['current_section'] == ".бнд":
            raise ValueError(
                "Ошибка: секция .бнд не поддерживает инициализированные данные "
                "(используйте .резб, .резс, .рездс, .резкс)"
            )
        string_tok = parser_expect(state, 'СТРОКА')
        state['parsed_lines'].append(f"DIRECTIVE:{word}:{state['current_section']}:{string_tok[1]}")

    # === Константы (запрещены в .бнд) ===
    elif word == '.константа':
        if state['current_section'] == ".бнд":
            raise ValueError(
                "Ошибка: секция .бнд не поддерживает инициализированные данные "
                "(используйте .резб, .резс, .рездс, .резкс)"
            )
        name = parser_expect(state, 'СЛОВО')[1]
        eq_tok = parser_peek(state)
        if eq_tok and eq_tok[0] == 'СЛОВО' and eq_tok[1] == '=':
            parser_next_token(state)
        value_tok = parser_expect_one_of(state, ['СЛОВО', 'ЧИСЛО'])
        state['parsed_lines'].append(f"DIRECTIVE:{word}:{name}:{value_tok[1]}")

    # === Байты (запрещены в .бнд) ===
    elif word == '.байт':
        if state['current_section'] == ".бнд":
            raise ValueError(
                "Ошибка: секция .бнд не поддерживает инициализированные данные "
                "(используйте .резб, .резс, .рездс, .резкс)"
            )
        bytes_list = []
        while True:
            tok = parser_peek(state)
            if tok is None or tok[0] == 'НОВСТР' or tok[0] == 'ЗАПЯТАЯ':
                if tok and tok[0] == 'ЗАПЯТАЯ':
                    parser_next_token(state)
                else:
                    break
            else:
                val_tok = parser_expect_one_of(state, ['СЛОВО', 'ЧИСЛО', 'СТРОКА'])
                bytes_list.append(val_tok[1])
        state['parsed_lines'].append(f"DIRECTIVE:{word}:{state['current_section']}:" + ",".join(bytes_list))

    # === Директивы резервирования (только в .бнд) ===
    elif word in ('.резб', '.резс', '.рездс', '.резкс'):
        if state['current_section'] != ".бнд":
            raise ValueError(
                f"Ошибка: директива {word} допустима только внутри секции .бнд"
            )
        count_tok = parser_expect(state, 'ЧИСЛО')
        count = int(count_tok[1])
        if count <= 0:
            raise ValueError(
                f"Ошибка: размер резервирования должен быть положительным целым числом"
            )
        state['parsed_lines'].append(
            f"DIRECTIVE:{word}:{state['current_section']}:{count}"
        )

    else:
        raise ValueError(f"Неизвестная директива: {word}")


# ==================== РАЗБОР ИНСТРУКЦИЙ ====================

def parse_instruction(state, mnemonic):
    """Разбор инструкции с операндами"""
    if mnemonic not in INSTRUCTIONS:
        raise ValueError(f"Неизвестная инструкция: {mnemonic}")

    operands = []
    while True:
        tok = parser_peek(state)
        if tok is None or tok[0] == 'НОВСТР':
            break
        if tok[0] == 'ЗАПЯТАЯ':
            parser_next_token(state)
            continue
        operands.append(parse_operand(state))

    str_operands = []
    for op in operands:
        if isinstance(op, tuple) and len(op) >= 2 and op[0] in ('absolute', 'register_indirect', 'complex'):
            str_operands.append(memory_operand_to_ast_string(op))
        else:
            str_operands.append(op)

    state['parsed_lines'].append(f"INSTR:{mnemonic}:{state['current_section']}:" + ",".join(str_operands))


# ==================== РАЗБОР ИНСТРУКЦИИ ИЛИ ДИРЕКТИВЫ ====================

def parse_instruction_or_directive(state):
    """Определяет, инструкция или директива, и вызывает нужный разбор"""
    tok = parser_peek(state)
    if tok is None or tok[0] == 'НОВСТР':
        return True

    if tok[0] != 'СЛОВО':
        raise ValueError(f"Ожидалось слово, получено: {tok}")

    word = parser_next_token(state)[1]

    if word.startswith('.'):
        parse_directive(state, word)
    else:
        parse_instruction(state, word)

    return True


# ==================== РАЗБОР СТРОКИ ====================

def parse_line(state):
    """Разбор одной строки (может содержать метку)"""
    tok = parser_peek(state)
    if tok is None:
        return False

    # Пропускаем маркер конца строки
    if tok[0] == 'НОВСТР':
        parser_next_token(state)
        tok = parser_peek(state)
        if tok is None:
            return False

    # Проверяем, есть ли метка (СЛОВО за которым следует ДВОЕТОЧИЕ)
    if tok[0] == 'СЛОВО':
        if state['pos'] + 1 < len(state['tokens']) and state['tokens'][state['pos'] + 1][0] == 'ДВОЕТОЧИЕ':
            label_name = parser_next_token(state)[1]
            parser_next_token(state)  # ДВОЕТОЧИЕ
            state['parsed_lines'].append(f"LABEL:{label_name}:{state['current_section']}")

            next_tok = parser_peek(state)
            if next_tok and next_tok[0] != 'НОВСТР':
                return parse_instruction_or_directive(state)
            return True

    return parse_instruction_or_directive(state)


# ==================== ГЛАВНЫЙ ЦИКЛ ====================

def parse_all(tokens):
    """Разбирает все токены, возвращает список строк AST"""
    state = parser_init(tokens)
    while state['pos'] < len(state['tokens']):
        parse_line(state)
    return state['parsed_lines']


# ==================== ЗАПИСЬ РЕЗУЛЬТАТА ====================

def write_ast(ast_lines, output_file):
    """Записывает строки AST в файл"""
    with open(output_file, 'w', encoding='utf-8') as f:
        for line in ast_lines:
            f.write(line + '\n')


# ==================== ТОЧКА ВХОДА ====================

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Использование: python kvs_parser.py <вход.токены> <выход.аст>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    tokens = read_tokens(input_file)
    ast_lines = parse_all(tokens)
    write_ast(ast_lines, output_file)
    print(f"Парсер: {len(ast_lines)} строк AST записано в {output_file}")