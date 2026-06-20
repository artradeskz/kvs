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
        
        # Пропускаем маркер конца строки
        if tok[0] == 'НОВСТР':
            self.next_token()
            tok = self.peek()
            if tok is None:
                return False
        
        # Проверяем, есть ли метка (СЛОВО за которым следует ДВОЕТОЧИЕ)
        if tok[0] == 'СЛОВО':
            if self.pos + 1 < len(self.tokens) and self.tokens[self.pos + 1][0] == 'ДВОЕТОЧИЕ':
                label_name = self.next_token()[1]
                self.next_token()  # ДВОЕТОЧИЕ
                self.parsed_lines.append(f"LABEL:{label_name}:{self.current_section}")
                
                next_tok = self.peek()
                if next_tok and next_tok[0] != 'НОВСТР':
                    return self.parse_instruction_or_directive()
                return True
        
        return self.parse_instruction_or_directive()
    
    def parse_instruction_or_directive(self):
        tok = self.peek()
        if tok is None or tok[0] == 'НОВСТР':
            return True
        
        if tok[0] != 'СЛОВО':
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
            label = self.expect('СЛОВО')[1]
            self.parsed_lines.append(f"DIRECTIVE:{word}:{label}")

        # === Строковые директивы (запрещены в .бнд) ===
        elif word in ('.строка_нуль', '.строка'):
            if self.current_section == ".бнд":
                raise ValueError(
                    "Ошибка: секция .бнд не поддерживает инициализированные данные "
                    "(используйте .резб, .резс, .рездс, .резкс)"
                )
            string_tok = self.expect('СТРОКА')
            self.parsed_lines.append(f"DIRECTIVE:{word}:{self.current_section}:{string_tok[1]}")

        # === Константы (запрещены в .бнд) ===
        elif word == '.константа':
            if self.current_section == ".бнд":
                raise ValueError(
                    "Ошибка: секция .бнд не поддерживает инициализированные данные "
                    "(используйте .резб, .резс, .рездс, .резкс)"
                )
            name = self.expect('СЛОВО')[1]
            eq_tok = self.peek()
            if eq_tok and eq_tok[0] == 'СЛОВО' and eq_tok[1] == '=':
                self.next_token()
            value_tok = self.expect_one_of(['СЛОВО', 'ЧИСЛО'])
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
                if tok is None or tok[0] == 'НОВСТР' or tok[0] == 'ЗАПЯТАЯ':
                    if tok and tok[0] == 'ЗАПЯТАЯ':
                        self.next_token()
                    else:
                        break
                else:
                    val_tok = self.expect_one_of(['СЛОВО', 'ЧИСЛО', 'СТРОКА'])
                    bytes_list.append(val_tok[1])
            self.parsed_lines.append(f"DIRECTIVE:{word}:{self.current_section}:" + ",".join(bytes_list))

        # === Директивы резервирования (только в .бнд) ===
        elif word in ('.резб', '.резс', '.рездс', '.резкс'):
            if self.current_section != ".бнд":
                raise ValueError(
                    f"Ошибка: директива {word} допустима только внутри секции .бнд"
                )
            count_tok = self.expect('ЧИСЛО')
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
        """Разбирает один операнд"""
        tok = self.peek()
        if tok is None:
            return None
        
        if tok[0] == 'СК_ОТКР':
            self.next_token()
            return self.parse_memory_operand()
        elif tok[0] == 'ЧИСЛО':
            return self.next_token()[1]
        elif tok[0] == 'СТРОКА':
            return self.next_token()[1]
        elif tok[0] == 'СЛОВО':
            return self.next_token()[1]
        else:
            raise ValueError(f"Неожиданный токен в операнде: {tok}")
    
    def parse_memory_operand(self):
        """Разбирает операнд памяти"""
        parts = []
        
        while True:
            tok = self.peek()
            if tok is None:
                raise ValueError("Незакрытая квадратная скобка")
            
            if tok[0] == 'СК_ЗАКР':
                self.next_token()
                break
            
            if tok[0] in ('СЛОВО', 'ЧИСЛО', 'ПЛЮС', 'МИНУС', 'ЗВЕЗДА'):
                parts.append(self.next_token()[1])
            else:
                raise ValueError(f"Неожиданный токен в адресации: {tok}")
        
        if len(parts) == 1:
            part = parts[0]
            if part in REGISTERS:
                return make_memory_operand('register_indirect', base_reg=part)
        
        expr = ' '.join(parts)
        return f"[{expr}]"
    
    def parse_instruction(self, mnemonic):
        if mnemonic not in INSTRUCTIONS:
            raise ValueError(f"Неизвестная инструкция: {mnemonic}")
        
        operands = []
        while True:
            tok = self.peek()
            if tok is None or tok[0] == 'НОВСТР':
                break
            if tok[0] == 'ЗАПЯТАЯ':
                self.next_token()
                continue
            operands.append(self.parse_operand())
        
        str_operands = []
        for op in operands:
            if isinstance(op, tuple) and len(op) >= 2 and op[0] in ('absolute', 'register_indirect', 'complex'):
                str_operands.append(memory_operand_to_ast_string(op))
            else:
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