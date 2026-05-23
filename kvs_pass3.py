#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Третий проход КВС
- Читает AST для получения констант
- Заменяет имена констант в 'исходная_команда' на их числовые значения
- Записывает результат в колонку 'команда_со_значениями'
- Поддерживает константы в операндах (как непосредственные значения)
"""

import sys
import csv


def read_ast(ast_file):
    """Читает AST файл и извлекает константы"""
    symbols = {}  # имя константы -> значение
    
    with open(ast_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            
            parts = line.split(':')
            if parts[0] == "DIRECTIVE" and len(parts) >= 4:
                directive = parts[1]
                if directive == '.константа':
                    name = parts[2]
                    value_str = parts[3]
                    if value_str.startswith('0x') or value_str.startswith('0X'):
                        value = int(value_str, 16)
                    else:
                        value = int(value_str)
                    symbols[name] = value
                    print(f"  константа: {name} = {value}")
    
    return symbols


def read_csv(csv_file):
    """Читает CSV файл и возвращает список записей и заголовки"""
    entries = []
    headers = []
    
    with open(csv_file, 'r', encoding='utf-8') as f:
        reader = csv.reader(f, delimiter=';')
        headers = next(reader)
        for row in reader:
            entries.append(row)
    
    return headers, entries


def substitute_constants(entries, headers, symbols):
    """Заменяет константы в исходной команде на их значения"""
    try:
        source_idx = headers.index('исходная_команда')
        source_with_values_idx = headers.index('команда_со_значениями')
    except ValueError as e:
        print(f"Ошибка: не найдена нужная колонка в CSV: {e}")
        sys.exit(1)
    
    substituted_count = 0
    
    for row in entries:
        source = row[source_idx].strip()
        if not source:
            continue
        
        # Копируем исходную команду
        new_source = source
        
        # Заменяем константы в команде
        for name, value in symbols.items():
            if name in new_source:
                # Заменяем имя константы на её значение
                new_source = new_source.replace(name, str(value))
        
        # Если команда изменилась, записываем в колонку команда_со_значениями
        if new_source != source:
            row[source_with_values_idx] = new_source
            substituted_count += 1
    
    return substituted_count


def save_csv(csv_file, headers, entries):
    """Сохраняет обновлённый CSV файл"""
    with open(csv_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f, delimiter=';')
        writer.writerow(headers)
        writer.writerows(entries)


def print_statistics(symbols_count, substituted_count, symbols):
    """Выводит статистику по заменам констант"""
    print(f"\n--- Статистика замены констант ---")
    print(f"  Всего констант в AST: {symbols_count}")
    print(f"  Заменено в командах: {substituted_count}")
    
    if symbols:
        print(f"\n--- Найденные константы ---")
        for name, value in sorted(symbols.items()):
            print(f"    {name} = {value}")


def main():
    if len(sys.argv) != 3:
        print("Использование: python kvs_pass3.py <аст.файл> <входной.csv>")
        print("  <аст.файл>   - файл с AST (например, программа.аст)")
        print("  <входной.csv> - CSV файл для обновления")
        sys.exit(1)
    
    ast_file = sys.argv[1]
    csv_file = sys.argv[2]
    
    print(f"\n=== Третий проход КВС ===")
    print(f"Чтение AST: {ast_file}")
    
    # Читаем константы из AST
    symbols = read_ast(ast_file)
    print(f"Найдено констант: {len(symbols)}")
    
    print(f"\nЧтение CSV: {csv_file}")
    headers, entries = read_csv(csv_file)
    
    print(f"\n--- Замена констант в командах ---")
    substituted_count = substitute_constants(entries, headers, symbols)
    
    print_statistics(len(symbols), substituted_count, symbols)
    
    # Сохраняем результат
    save_csv(csv_file, headers, entries)
    print(f"\nCSV сохранен: {csv_file}")
    print(f"Колонка 'команда_со_значениями' обновлена")


if __name__ == "__main__":
    main()