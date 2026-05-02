#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Лексер КВС
Принимает: исходный .квс файл
Выдаёт: текстовый файл с токенами (по одному токену на строку)
Формат вывода: ТИП:ЗНАЧЕНИЕ
"""

import sys

def error_unterminated_string(line_num):
    return f"Незакрытая кавычка в строке на строке {line_num}"

def tokenize_line(line, line_num):
    """Разбирает строку в токены"""
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
                    # Оставляем escape-последовательности как есть
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
        
        if ch == ',':
            tokens.append(('COMMA', ','))
            i += 1
            continue
        
        if ch == ':':
            tokens.append(('COLON', ':'))
            i += 1
            continue
        
        j = i
        while j < n and not (line[j].isspace() or line[j] in ',:;'):
            j += 1
        word = line[i:j]
        if word:
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