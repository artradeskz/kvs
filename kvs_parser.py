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
        if word == '.текст':
            self.current_section = ".text"
            self.parsed_lines.append(f"DIRECTIVE:{word}")
        elif word == '.данные':
            self.current_section = ".data"
            self.parsed_lines.append(f"DIRECTIVE:{word}")
        elif word == '.глобал':
            label = self.expect('WORD')[1]
            self.parsed_lines.append(f"DIRECTIVE:{word}:{label}")
        elif word in ('.строка_нуль', '.строка'):
            string_tok = self.expect('STRING')
            self.parsed_lines.append(f"DIRECTIVE:{word}:{self.current_section}:{string_tok[1]}")
        elif word == '.константа':
            name = self.expect('WORD')[1]
            # Пропускаем '=', если есть
            eq_tok = self.peek()
            if eq_tok and eq_tok[0] == 'WORD' and eq_tok[1] == '=':
                self.next_token()
            # Значение может быть WORD или NUMBER
            value_tok = self.expect_one_of(['WORD', 'NUMBER'])
            self.parsed_lines.append(f"DIRECTIVE:{word}:{name}:{value_tok[1]}")
        elif word == '.байт':
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
        else:
            raise ValueError(f"Неизвестная директива: {word}")
    
    def parse_operand(self):
        """
        Разбирает один операнд.
        Возвращает строковое представление операнда.
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
        Разбирает операнд памяти вида:
        [регистр]
        [число]
        [регистр + смещение]
        [регистр + регистр*масштаб]
        [регистр + регистр*масштаб + смещение]
        """
        self.expect('LBRACKET')
        
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
        
        # Собираем выражение
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
        
        self.parsed_lines.append(f"INSTR:{mnemonic}:{self.current_section}:" + ",".join(operands))
    
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