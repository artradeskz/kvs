#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Тестовый скрипт для проверки инструкций с фиксированной длиной
Запуск: python3 test_fixed_instructions.py [--keep-files]
"""

import sys
import os
import subprocess
import csv

# ANSI color codes
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
RESET = '\033[0m'

# === ТЕСТОВЫЙ ИСХОДНИК ===
TEST_SOURCE = '''.глобал _start
.текст

_start:
    нет_операции
    вызов_системы
    вернуться
    втолкнуть раикс
    втолкнуть р8
    вытолкнуть раикс
    вытолкнуть р8
    переместить раикс, рбикс
    переместить р8, р9
    сравнить раикс, рбикс
    сравнить р8, р9
    проверить раикс, рбикс
    проверить р8, р9
    прибавить раикс, рбикс
    прибавить р8, р9
    вычесть раикс, рбикс
    вычесть р8, р9
    и раикс, рбикс
    и р8, р9
    или раикс, рбикс
    или р8, р9
    исключающее_или раикс, рбикс
    исключающее_или р8, р9
    увеличить раикс
    увеличить р8
    увеличить еаикс
    уменьшить раикс
    уменьшить р8
    уменьшить еаикс
    инвертировать раикс
    инвертировать еаикс
    отрицать раикс
    отрицать еаикс
    переместить_имм раикс, 10
    переместить_имм рбикс, 5
    умножить рбикс
    переместить_имм раикс, 100
    переместить_имм рбикс, 7
    разделить рбикс
    умножить_знаковое рбикс
    разделить_знаковое рбикс
    сдвиг_влево раикс, 2
    сдвиг_вправо раикс, 2
    сдвиг_арифметический_вправо раикс, 2
    вращать_влево раикс, 2
    вращать_вправо раикс, 2
    переход метка_длинная
    короткий_переход метка_короткая
    цикл метка_короткая
    вызвать метка_длинная

метка_длинная:
    нет_операции
    нет_операции
    нет_операции

метка_короткая:
    нет_операции

    переместить_имм раикс, 60
    переместить_имм рдикс, 0
    вызов_системы
'''


# === ОЖИДАЕМЫЕ РЕЗУЛЬТАТЫ ===
# Для инструкций с фиксированным кодом — полная проверка
EXPECTED_INSTRUCTIONS_FULL = {
    "нет_операции": [0x90],
    "вызов_системы": [0x0F, 0x05],
    "вернуться": [0xC3],
    "втолкнуть раикс": [0x50],
    "втолкнуть р8": [0x41, 0x50],
    "вытолкнуть раикс": [0x58],
    "вытолкнуть р8": [0x41, 0x58],
    "переместить раикс, рбикс": [0x48, 0x89, 0xD8],
    "переместить р8, р9": [0x4D, 0x89, 0xC8],
    "сравнить раикс, рбикс": [0x48, 0x39, 0xD8],
    "сравнить р8, р9": [0x4D, 0x39, 0xC8],
    "проверить раикс, рбикс": [0x48, 0x85, 0xD8],
    "проверить р8, р9": [0x4D, 0x85, 0xC8],
    "прибавить раикс, рбикс": [0x48, 0x01, 0xD8],
    "прибавить р8, р9": [0x4D, 0x01, 0xC8],
    "вычесть раикс, рбикс": [0x48, 0x29, 0xD8],
    "вычесть р8, р9": [0x4D, 0x29, 0xC8],
    "и раикс, рбикс": [0x48, 0x21, 0xD8],
    "и р8, р9": [0x4D, 0x21, 0xC8],
    "или раикс, рбикс": [0x48, 0x09, 0xD8],
    "или р8, р9": [0x4D, 0x09, 0xC8],
    "исключающее_или раикс, рбикс": [0x48, 0x31, 0xD8],
    "исключающее_или р8, р9": [0x4D, 0x31, 0xC8],
    "увеличить раикс": [0x48, 0xFF, 0xC0],
    "увеличить р8": [0x49, 0xFF, 0xC0],
    "увеличить еаикс": [0xFF, 0xC0],
    "уменьшить раикс": [0x48, 0xFF, 0xC8],
    "уменьшить р8": [0x49, 0xFF, 0xC8],
    "уменьшить еаикс": [0xFF, 0xC8],
    "инвертировать раикс": [0x48, 0xF7, 0xD0],
    "инвертировать еаикс": [0xF7, 0xD0],
    "отрицать раикс": [0x48, 0xF7, 0xD8],
    "отрицать еаикс": [0xF7, 0xD8],
    "умножить рбикс": [0x48, 0xF7, 0xE0],
    "разделить рбикс": [0x48, 0xF7, 0xF0],
    "умножить_знаковое рбикс": [0x48, 0xF7, 0xE8],
    "разделить_знаковое рбикс": [0x48, 0xF7, 0xF8],
    "сдвиг_влево раикс, 2": [0x48, 0xC1, 0xE0, 0x02],
    "сдвиг_вправо раикс, 2": [0x48, 0xC1, 0xE8, 0x02],
    "сдвиг_арифметический_вправо раикс, 2": [0x48, 0xC1, 0xF8, 0x02],
    "вращать_влево раикс, 2": [0x48, 0xC1, 0xC0, 0x02],
    "вращать_вправо раикс, 2": [0x48, 0xC1, 0xC8, 0x02],
    "переместить_имм раикс, 10": [0x48, 0xB8, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    "переместить_имм рбикс, 5": [0x48, 0xBB, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    "переместить_имм раикс, 100": [0x48, 0xB8, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    "переместить_имм рбикс, 7": [0x48, 0xBB, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    "переместить_имм раикс, 60": [0x48, 0xB8, 0x3C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    "переместить_имм рдикс, 0": [0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
}

# Инструкции, у которых проверяем только opcode (первые байты)
EXPECTED_INSTRUCTIONS_PREFIX = {
    "переход метка_длинная": [0xE9],      # JMP rel32
    "короткий_переход метка_короткая": [0xEB],  # JMP SHORT
    "цикл метка_короткая": [0xE2],        # LOOP
    "вызвать метка_длинная": [0xE8],      # CALL rel32
}


def read_csv_instructions(csv_file):
    """Читает CSV и возвращает словарь {мнемоника: [байты]}"""
    instructions = {}
    current_mnemonic = None
    current_bytes = []
    
    with open(csv_file, 'r', encoding='utf-8') as f:
        reader = csv.reader(f, delimiter=';')
        header = next(reader)
        
        for row in reader:
            if len(row) < 4:
                continue
            
            cmd = row[3].strip()
            byte_str = row[1].strip()
            
            if not byte_str:
                continue
                
            byte_val = int(byte_str, 16)
            
            if cmd:
                if current_mnemonic and current_bytes:
                    instructions[current_mnemonic] = current_bytes
                current_mnemonic = cmd
                current_bytes = [byte_val]
            else:
                if current_mnemonic:
                    current_bytes.append(byte_val)
    
    if current_mnemonic and current_bytes:
        instructions[current_mnemonic] = current_bytes
    
    return instructions


def run_tests(generated_instructions):
    """Сравнивает сгенерированные инструкции с ожидаемыми"""
    errors = []
    missing = []
    
    # Проверяем инструкции с полным совпадением
    for mnemonic, expected_bytes in EXPECTED_INSTRUCTIONS_FULL.items():
        if mnemonic not in generated_instructions:
            missing.append(mnemonic)
            continue
        
        actual_bytes = generated_instructions[mnemonic]
        if actual_bytes != expected_bytes:
            expected_hex = ' '.join(f'{b:02X}' for b in expected_bytes)
            actual_hex = ' '.join(f'{b:02X}' for b in actual_bytes)
            errors.append(f"  {mnemonic}: ожидалось [{expected_hex}], получено [{actual_hex}]")
    
    # Проверяем инструкции только по префиксу
    for mnemonic, expected_prefix in EXPECTED_INSTRUCTIONS_PREFIX.items():
        if mnemonic not in generated_instructions:
            missing.append(mnemonic)
            continue
        
        actual_bytes = generated_instructions[mnemonic]
        prefix_len = len(expected_prefix)
        
        if len(actual_bytes) < prefix_len:
            errors.append(f"  {mnemonic}: слишком короткая ({len(actual_bytes)} байт, ожидалось минимум {prefix_len})")
        elif actual_bytes[:prefix_len] != expected_prefix:
            expected_hex = ' '.join(f'{b:02X}' for b in expected_prefix)
            actual_hex = ' '.join(f'{b:02X}' for b in actual_bytes[:prefix_len])
            errors.append(f"  {mnemonic}: префикс [{expected_hex}...], получено [{actual_hex}...]")
    
    return errors, missing


def cleanup(files_to_delete, keep_files=False):
    """Удаляет временные файлы"""
    if keep_files:
        print("\nФлаг --keep-files указан, промежуточные файлы сохранены:")
        for f in files_to_delete:
            if os.path.exists(f):
                print(f"   {f}")
        return
    
    deleted = []
    for f in files_to_delete:
        if os.path.exists(f):
            os.remove(f)
            deleted.append(f)
    
    if deleted:
        print(f"\nУдалено {len(deleted)} временных файлов")


def main():
    keep_files = '--keep-files' in sys.argv or '-k' in sys.argv
    
    base_name = "т1"
    source_file = f"{base_name}.квс"
    tokens_file = f"{base_name}.токены"
    ast_file = f"{base_name}.аст"
    p1_file = f"{base_name}.проход1"
    csv_file = f"{base_name}.csv"
    elf_file = f"{base_name}.elf"

    
    temp_files = [tokens_file, ast_file, p1_file, csv_file, elf_file]
    
    print("КВС Тестировщик - Инструкции с фиксированной длиной\n")
    print("=" * 60)
    
    # Шаг 1: Создание исходного файла
    print("Шаг 1: Создание тестового исходника...")
    with open(source_file, 'w', encoding='utf-8') as f:
        f.write(TEST_SOURCE)
    print(f"   Создан {source_file}")
    
    # Шаг 2: Компиляция
    print("\nШаг 2: Компиляция...")
    result = subprocess.run(
        [sys.executable, "kvs_build.py", source_file],
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        print("   ОШИБКА компиляции:")
        print(result.stderr)
        print("\nОставшиеся файлы для отладки:")
        print(f"   {source_file}")
        if os.path.exists(csv_file):
            print(f"   {csv_file}")
        sys.exit(1)
    
    print("   Компиляция успешна")
    
    # Шаг 3: Проверка результатов
    print("\nШаг 3: Проверка сгенерированного кода...")
    
    if not os.path.exists(csv_file):
        print(f"   Файл {csv_file} не найден!")
        sys.exit(1)
    
    generated_instructions = read_csv_instructions(csv_file)
    errors, missing = run_tests(generated_instructions)
    
    # Вывод результатов
    print("\n" + "=" * 60)
    print("РЕЗУЛЬТАТЫ ТЕСТИРОВАНИЯ:")
    print("=" * 60)
    
    if missing:
        print(f"\n{YELLOW}ОТСУТСТВУЮТ ИНСТРУКЦИИ ({len(missing)}):{RESET}")
        for m in missing[:10]:
            print(f"   - {m}")
        if len(missing) > 10:
            print(f"   ... и ещё {len(missing)-10}")
    
    if errors:
        print(f"\n{RED}НАЙДЕНО {len(errors)} ОШИБОК В КОДЕ:{RESET}")
        for err in errors:
            print(err)
        success = False
    else:
        print(f"\n{GREEN}НЕТ ОШИБОК! ВСЕ ИНСТРУКЦИИ ЗАКОДИРОВАНЫ ВЕРНО!{RESET}")
        success = True
    
    # Статистика
    print(f"\nСтатистика:")
    print(f"   Ожидалось инструкций (полная проверка): {len(EXPECTED_INSTRUCTIONS_FULL)}")
    print(f"   Ожидалось инструкций (проверка префикса): {len(EXPECTED_INSTRUCTIONS_PREFIX)}")
    print(f"   Сгенерировано инструкций: {len(generated_instructions)}")
    
    # Шаг 4: Очистка
    cleanup([source_file] + temp_files, keep_files)
    
    # Финальный вердикт
    print("\n" + "=" * 60)
    if success:
        print(f"{GREEN}ТЕСТЫ ПРОЙДЕНЫ УСПЕШНО!{RESET}")
        sys.exit(0)
    else:
        print(f"{RED}ТЕСТЫ НЕ ПРОЙДЕНЫ!{RESET}")
        sys.exit(1)


if __name__ == "__main__":
    main()