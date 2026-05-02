#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Главный сборочный скрипт КВС
Последовательно запускает все этапы компиляции
"""

import sys
import subprocess

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Использование: python kvs_build.py <файл.квс>")
        sys.exit(1)
    
    source_file = sys.argv[1]
    if not source_file.endswith('.квс'):
        print("Ошибка: файл должен иметь расширение .квс")
        sys.exit(1)
    
    base_name = source_file[:-4]
    
    tokens_file = base_name + ".токены"
    ast_file = base_name + ".аст"
    pass1_file = base_name + ".проход1"
    csv_file = base_name + ".csv"
    elf_file = base_name + ".elf"
    
    stages = [
        ("kvs_lexer.py", [source_file, tokens_file], "Лексический анализ"),
        ("kvs_parser.py", [tokens_file, ast_file], "Парсинг"),
        ("kvs_pass1.py", [ast_file, pass1_file], "Первый проход"),
        ("kvs_pass2.py", [ast_file, pass1_file, csv_file], "Второй проход и генерация CSV"),
        ("kvs_builder.py", [csv_file, pass1_file, elf_file], "Сборка ELF"),
    ]
    
    for script, args, description in stages:
        print(f"\n=== {description} ===")
        cmd = [sys.executable, script] + args
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"ОШИБКА на этапе '{description}':")
            print(result.stderr)
            sys.exit(1)
        
        print(result.stdout)
    
    print(f"\n=== Компиляция успешно завершена ===")
    print(f"Исполняемый файл: {elf_file}")
    print(f"Запустить: ./{elf_file}")