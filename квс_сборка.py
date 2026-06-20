#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""квс_сборка.py
Главный сборочный скрипт КВС
Последовательно запускает все этапы компиляции
"""

import sys
import subprocess

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Использование: python квс_сборка.py <файл.квс>")
        sys.exit(1)
    
    source_file = sys.argv[1]
    if not source_file.endswith('.квс'):
        print("Ошибка: файл должен иметь расширение .квс")
        sys.exit(1)
    
    base_name = source_file[:-4]
    
    tokens_file = base_name + ".токены"
    ast_file = base_name + ".аст"
    csv_file = base_name + ".csv"
    elf_file = base_name + ".elf"
    
    stages = [
        ("квс_лексер.py", [source_file, tokens_file], "Лексический анализ"),
        ("квс_парсер.py", [tokens_file, ast_file], "Парсинг"),
        ("квс_проход1.py", [ast_file, csv_file], "Первый проход: генерация кода и CSV"),
        ("квс_проход2.py", [csv_file], "2 проход"),
        ("квс_проход3.py", [ast_file, csv_file], "3 проход"),
        ("квс_проход4.py", [csv_file], "4 проход"),
        ("квс_проход5.py", [csv_file], "5 проход"),
        ("квс_проход6.py", [csv_file], "6 проход"),
        ("квс_финсбор.py", [csv_file, elf_file], "Сборка ELF"),
    ]
    
    for script, args, description in stages:
        print(f"\n=== {description} ===")
        cmd = [sys.executable, script] + args
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"ОШИБКА на этапе '{description}':")
            print(result.stderr)
            if result.stdout:
                print(result.stdout)
            sys.exit(1)
        
        if result.stdout:
            print(result.stdout)
    
    #print(f"\n=== Компиляция успешно завершена ===")
    #print(f"Исполняемый файл: {elf_file}")
    #print(f"Запустить: ./{elf_file}")