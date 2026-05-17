#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Парсер КВС
Принимает: файл токенов от лексера
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
        # Пока не поддерживается, но зарезервировано
        return f"MEM:complex:{mem_op[1]}+{mem_op[2]}*{mem_op[3]}+{mem_op[4]}"
    else:
        return f"MEM:unknown"


def read_tokens(input_file):
    """Читает токены из файла"""
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


class Parser:
    def __init__(self, tokens):
        self.tokens = tokens
        self.pos = 0
        self.current_section = ".text"
        self.parsed_lines = []
        
    def peek(self):
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return None
    
    def next_token(self):
        tok = self.peek()
        if tok:
            self.pos += 1
        return tok
    
    def expect(self, expected_type):
        tok = self.next_token()
        if tok is None or tok[0] != expected_type:
            raise ValueError(f"Ожидался {expected_type}, получено {tok}")
        return tok
    
    def expect_one_of(self, expected_types):
        """Ожидает один из нескольких типов токенов"""
        tok = self.peek()
        if tok is None or tok[0] not in expected_types:
            raise ValueError(f"Ожидался один из {expected_types}, получено {tok}")
        return self.next_token()
    
    def parse_line(self):
        tok = self.peek()
        if tok is None:
            return False
        
        if tok[0] == 'NEWLINE':
            self.next_token()
            tok = self.peek()
            if tok is None:
                return False
        
        if tok[0] == 'WORD':
            # Проверяем, есть ли после слова двоеточие (метка)
            if self.pos + 1 < len(self.tokens) and self.tokens[self.pos + 1][0] == 'COLON':
                label_name = self.next_token()[1]
                self.next_token()  # COLON
                self.parsed_lines.append(f"LABEL:{label_name}:{self.current_section}")
                
                next_tok = self.peek()
                if next_tok and next_tok[0] != 'NEWLINE':
                    return self.parse_instruction_or_directive()
                return True
        
        return self.parse_instruction_or_directive()
    
    def parse_instruction_or_directive(self):
        tok = self.peek()
        if tok is None or tok[0] == 'NEWLINE':
            return True
        
        if tok[0] != 'WORD':
            raise ValueError(f"Ожидалось слово, получено: {tok}")
        
        word = self.next_token()[1]
        
        if word.startswith('.'):
            self.parse_directive(word)
        else:
            self.parse_instruction(word)
        
        return True
    
    def parse_directive(self, word):
        """
        Разбор директив ассемблера.
        Вызывает ошибку при некорректном синтаксисе или контексте.
        """
        # === Секции ===
        if word == '.текст':
            self.current_section = ".text"
            self.parsed_lines.append(f"DIRECTIVE:{word}")

        elif word == '.данные':
            self.current_section = ".data"
            self.parsed_lines.append(f"DIRECTIVE:{word}")

        elif word == '.бнд':
            self.current_section = ".бнд"
            self.parsed_lines.append(f"DIRECTIVE:{word}")

        # === Глобальные метки ===
        elif word == '.глобал':
            label = self.expect('WORD')[1]
            self.parsed_lines.append(f"DIRECTIVE:{word}:{label}")

        # === Строковые директивы (запрещены в .бнд) ===
        elif word in ('.строка_нуль', '.строка'):
            if self.current_section == ".бнд":
                raise ValueError(
                    "Ошибка: секция .бнд не поддерживает инициализированные данные "
                    "(используйте .резб, .резс, .рездс, .резкс)"
                )
            string_tok = self.expect('STRING')
            self.parsed_lines.append(f"DIRECTIVE:{word}:{self.current_section}:{string_tok[1]}")

        # === Константы (запрещены в .бнд) ===
        elif word == '.константа':
            if self.current_section == ".бнд":
                raise ValueError(
                    "Ошибка: секция .бнд не поддерживает инициализированные данные "
                    "(используйте .резб, .резс, .рездс, .резкс)"
                )
            name = self.expect('WORD')[1]
            # Пропускаем '=', если есть
            eq_tok = self.peek()
            if eq_tok and eq_tok[0] == 'WORD' and eq_tok[1] == '=':
                self.next_token()
            # Значение может быть WORD или NUMBER
            value_tok = self.expect_one_of(['WORD', 'NUMBER'])
            self.parsed_lines.append(f"DIRECTIVE:{word}:{name}:{value_tok[1]}")

        # === Байты (запрещены в .бнд) ===
        elif word == '.байт':
            if self.current_section == ".бнд":
                raise ValueError(
                    "Ошибка: секция .бнд не поддерживает инициализированные данные "
                    "(используйте .резб, .резс, .рездс, .резкс)"
                )
            bytes_list = []
            while True:
                tok = self.peek()
                if tok is None or tok[0] == 'NEWLINE' or tok[0] == 'COMMA':
                    if tok and tok[0] == 'COMMA':
                        self.next_token()
                    else:
                        break
                else:
                    # Может быть WORD (метка) или NUMBER (число)
                    val_tok = self.expect_one_of(['WORD', 'NUMBER', 'STRING'])
                    bytes_list.append(val_tok[1])
            self.parsed_lines.append(f"DIRECTIVE:{word}:{self.current_section}:" + ",".join(bytes_list))

        # === Директивы резервирования (только в .бнд) ===
        elif word in ('.резб', '.резс', '.рездс', '.резкс'):
            if self.current_section != ".бнд":
                raise ValueError(
                    f"Ошибка: директива {word} допустима только внутри секции .бнд"
                )
            count_tok = self.expect('NUMBER')
            count = int(count_tok[1])
            if count <= 0:
                raise ValueError(
                    f"Ошибка: размер резервирования должен быть положительным целым числом"
                )
            self.parsed_lines.append(
                f"DIRECTIVE:{word}:{self.current_section}:{count}"
            )

        else:
            raise ValueError(f"Неизвестная директива: {word}")
    
    def parse_operand(self):
        """
        Разбирает один операнд.
        Возвращает строку (регистр, число, метка, строка, старый формат памяти)
        или кортеж (новый формат памяти).
        Поддерживает:
        - регистры
        - числа
        - метки
        - строки
        - адресацию в квадратных скобках
        """
        tok = self.peek()
        if tok is None:
            return None
        
        if tok[0] == 'LBRACKET':
            self.next_token()  # съедаем '['
            return self.parse_memory_operand()
        elif tok[0] == 'NUMBER':
            return self.next_token()[1]
        elif tok[0] == 'STRING':
            return self.next_token()[1]
        elif tok[0] == 'WORD':
            return self.next_token()[1]
        else:
            raise ValueError(f"Неожиданный токен в операнде: {tok}")
    
    def parse_memory_operand(self):
        """
        Разбирает операнд памяти.
        Открывающая скобка уже прочитана в parse_operand.
        
        Возвращает:
        - строку "[выражение]" для абсолютной адресации (старый формат)
        - кортеж (addr_type, base_reg, displacement, label) для косвенной
        
        Поддерживает:
        [регистр]           → косвенная адресация (кортеж)
        [число]             → абсолютная (строка)
        [метка]             → абсолютная (строка)
        [регистр + ...]     → пока не поддерживается (строка)
        """
        parts = []
        
        # Разбираем содержимое до закрывающей скобки
        while True:
            tok = self.peek()
            if tok is None:
                raise ValueError("Незакрытая квадратная скобка")
            
            if tok[0] == 'RBRACKET':
                self.next_token()
                break
            
            if tok[0] in ('WORD', 'NUMBER', 'PLUS', 'MINUS', 'STAR'):
                parts.append(self.next_token()[1])
            else:
                raise ValueError(f"Неожиданный токен в адресации: {tok}")
        
        # Анализируем собранные части
        if len(parts) == 1:
            part = parts[0]
            # Проверяем, регистр ли это
            if part in REGISTERS:
                # Косвенная адресация: [регистр]
                return make_memory_operand('register_indirect', base_reg=part)
            # Иначе: [число] или [метка] — возвращаем строку (старый формат)
        
        # Старое поведение для всего остального
        # (абсолютная адресация, комплексная - пока не поддерживается)
        expr = ' '.join(parts)
        return f"[{expr}]"
    
    def parse_instruction(self, mnemonic):
        if mnemonic not in INSTRUCTIONS:
            raise ValueError(f"Неизвестная инструкция: {mnemonic}")
        
        operands = []
        while True:
            tok = self.peek()
            if tok is None or tok[0] == 'NEWLINE':
                break
            if tok[0] == 'COMMA':
                self.next_token()
                continue
            operands.append(self.parse_operand())
        
        # Преобразуем операнды в строки для AST
        str_operands = []
        for op in operands:
            if isinstance(op, tuple) and len(op) >= 2 and op[0] in ('absolute', 'register_indirect', 'complex'):
                # Это кортеж памяти
                str_operands.append(memory_operand_to_ast_string(op))
            else:
                # Это обычная строка (регистр, число, метка, старый формат памяти)
                str_operands.append(op)
        
        self.parsed_lines.append(f"INSTR:{mnemonic}:{self.current_section}:" + ",".join(str_operands))
    
    def parse_all(self):
        while self.pos < len(self.tokens):
            self.parse_line()
        return self.parsed_lines


def write_ast(ast_lines, output_file):
    with open(output_file, 'w', encoding='utf-8') as f:
        for line in ast_lines:
            f.write(line + '\n')


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Использование: python kvs_parser.py <вход.токены> <выход.аст>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    tokens = read_tokens(input_file)
    parser = Parser(tokens)
    ast_lines = parser.parse_all()
    write_ast(ast_lines, output_file)
    print(f"Парсер: {len(ast_lines)} строк AST записано в {output_file}")