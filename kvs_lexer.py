#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Лексер КВС
Принимает: исходный .квс файл
Выдаёт: текстовый файл с токенами (по одному токену на строку)
Формат вывода: ТИП:ЗНАЧЕНИЕ

Поддерживает сложную адресацию:
- [ ] - квадратные скобки
- + - плюс
- - - минус
- * - звёздочка (умножение/масштаб)
- NUMBER - числа (десятичные, шестнадцатеричные, отрицательные)
"""

import sys

def error_unterminated_string(line_num):
    return f"Незакрытая кавычка в строке на строке {line_num}"

def is_hex_number(s):
    """Проверяет, является ли строка шестнадцатеричным числом (0x... или 0X...)"""
    if len(s) < 3:
        return False
    if not (s[0] == '0' and (s[1] == 'x' or s[1] == 'X')):
        return False
    for ch in s[2:]:
        if not (('0' <= ch <= '9') or ('a' <= ch <= 'f') or ('A' <= ch <= 'F')):
            return False
    return True

def is_dec_number(s):
    """Проверяет, является ли строка десятичным числом (возможно с минусом)"""
    if not s:
        return False
    start = 0
    if s[0] == '-':
        if len(s) == 1:
            return False
        start = 1
    for ch in s[start:]:
        if ch < '0' or ch > '9':
            return False
    return True

def tokenize_line(line, line_num):
    """Разбирает строку в токены"""
    # Удаляем комментарии
    semi = -1
    for idx in range(len(line)):
        if line[idx] == ';':
            semi = idx
            break
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
        
        # Пропускаем пробелы
        if ch == ' ' or ch == '\t':
            i += 1
            continue
        
        # Строковые литералы
        if ch == '"':
            i += 1
            s = ''
            while i < n and line[i] != '"':
                if line[i] == '\\' and i + 1 < n:
                    s += '\\' + line[i + 1]
                    i += 2
                else:
                    s += line[i]
                    i += 1
            if i >= n:
                raise ValueError(error_unterminated_string(line_num))
            i += 1
            tokens.append(('STRING', s))
            continue
        
        # Одиночные символы-разделители
        if ch == ',':
            tokens.append(('COMMA', ','))
            i += 1
            continue
        
        if ch == ':':
            tokens.append(('COLON', ':'))
            i += 1
            continue
        
        # ТОКЕНЫ ДЛЯ СЛОЖНОЙ АДРЕСАЦИИ
        if ch == '[':
            tokens.append(('LBRACKET', '['))
            i += 1
            continue
        
        if ch == ']':
            tokens.append(('RBRACKET', ']'))
            i += 1
            continue
        
        if ch == '+':
            tokens.append(('PLUS', '+'))
            i += 1
            continue
        
        if ch == '-':
            tokens.append(('MINUS', '-'))
            i += 1
            continue
        
        if ch == '*':
            tokens.append(('STAR', '*'))
            i += 1
            continue
        
        # Слова, числа, метки
        j = i
        while j < n and not (line[j] in ' \t,;:[]+*-'):
            j += 1
        word = line[i:j]
        
        if word:
            # Определяем тип токена
            if is_hex_number(word):
                tokens.append(('NUMBER', word))
            elif is_dec_number(word):
                tokens.append(('NUMBER', word))
            else:
                tokens.append(('WORD', word))
        
        i = j
    
    return tokens

def lex_source(source_text):
    """Лексирует весь исходный текст"""
    lines = source_text.split('\n')
    all_tokens = []
    
    for line_num, line in enumerate(lines, start=1):
        try:
            tokens = tokenize_line(line, line_num)
            if tokens:
                all_tokens.append(('NEWLINE', str(line_num)))
                for tok_type, tok_value in tokens:
                    all_tokens.append((tok_type, tok_value))
        except ValueError as e:
            print(f"Ошибка лексера: {e}", file=sys.stderr)
            sys.exit(1)
    
    return all_tokens

def write_tokens(tokens, output_file):
    """Записывает токены в файл"""
    with open(output_file, 'w', encoding='utf-8') as f:
        for tok_type, tok_value in tokens:
            f.write(f"{tok_type}:{tok_value}\n")

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

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Использование: python kvs_lexer.py <вход.квс> <выход.токены>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            source_text = f.read()
    except FileNotFoundError:
        print(f"Ошибка: файл '{input_file}' не найден.", file=sys.stderr)
        sys.exit(1)
    
    tokens = lex_source(source_text)
    write_tokens(tokens, output_file)
    print(f"Лексер: {len(tokens)} токенов записано в {output_file}")