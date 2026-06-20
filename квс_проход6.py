#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Шестой проход КВС — сортировка CSV по адресам
- Сортирует все записи по числовому значению адреса
- Записи с адресом "BSS" помещает в конец (после всех реальных адресов)
- Обеспечивает правильный порядок байтов в итоговом ELF-файле
"""

import sys
import csv


def get_addr_value(addr_str):
    """
    Преобразует адрес в число для сортировки
    BSS и пустые адреса отправляются в конец (большое число)
    """
    if not addr_str or addr_str == '':
        return 999999999  # Пустые адреса в конец
    if addr_str == 'BSS':
        return 999999999  # BSS в самый конец (после всех реальных адресов)
    if addr_str.startswith('0x'):
        try:
            return int(addr_str, 16)
        except ValueError:
            return 999999999
    return 999999999


def sort_csv_by_address(input_csv, output_csv):
    """
    Сортирует CSV по адресам (числовым значениям)
    BSS и пустые адреса помещаются в конец
    
    Args:
        input_csv: входной CSV файл
        output_csv: выходной CSV файл
    """
    
    print(f"\n=== ШЕСТОЙ ПРОХОД КВС: сортировка CSV ===")
    print(f"Чтение: {input_csv}")
    
    # Читаем CSV
    with open(input_csv, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f, delimiter=';')
        fieldnames = reader.fieldnames
        rows = list(reader)
    
    print(f"Найдено записей: {len(rows)}")
    
    # Подсчёт статистики до сортировки
    bss_count = sum(1 for row in rows if row.get('адрес') == 'BSS')
    empty_count = sum(1 for row in rows if not row.get('адрес') or row.get('адрес') == '')
    normal_count = len(rows) - bss_count - empty_count
    
    print(f"  Обычных записей (с числовыми адресами): {normal_count}")
    print(f"  BSS-записей: {bss_count}")
    print(f"  Пустых адресов: {empty_count}")
    
    # Сортировка
    def sort_key(row):
        addr = row.get('адрес', '')
        value = get_addr_value(addr)
        return (value, 0)
    
    rows.sort(key=sort_key)
    
    # Записываем отсортированный CSV
    with open(output_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, delimiter=';', restval='')
        writer.writeheader()
        writer.writerows(rows)
    
    print(f"\n✅ CSV отсортирован и сохранён: {output_csv}")
    
    # Показываем первые 10 адресов для проверки
    print("\n📊 Первые 10 адресов после сортировки:")
    for i, row in enumerate(rows[:10]):
        addr = row.get('адрес', '')
        seg = row.get('сегмент', '')
        source = row.get('исходная_команда', '')[:30]
        print(f"  {i+1:2d}. {addr:12s} [{seg:10s}] {source}")
    
    # Показываем последние 5 адресов (должны быть BSS)
    if bss_count > 0:
        print("\n📊 Последние 5 записей (BSS в конце):")
        for i, row in enumerate(rows[-5:]):
            addr = row.get('адрес', '')
            seg = row.get('сегмент', '')
            source = row.get('исходная_команда', '')[:30]
            print(f"  {len(rows)-5+i+1:2d}. {addr:12s} [{seg:10s}] {source}")
    
    # Проверка: убеждаемся, что после сортировки нет числовых адресов после BSS
    found_bss = False
    for row in rows:
        addr = row.get('адрес', '')
        if addr == 'BSS':
            found_bss = True
        elif found_bss and addr and addr != '' and addr.startswith('0x'):
            print(f"\n⚠️  ВНИМАНИЕ: Найден числовой адрес {addr} после BSS!")
            print("   Это может указывать на проблему в данных.")
            break
    else:
        if found_bss:
            print("\n✅ Проверка пройдена: все BSS-записи в конце, числовых адресов после них нет.")
        else:
            print("\n✅ BSS-записей не найдено.")


def main():
    if len(sys.argv) not in (2, 3):
        print("Использование: python kvs_pass6.py <входной.csv> [выходной.csv]")
        print("  Если выходной не указан, перезаписывается входной файл")
        sys.exit(1)
    
    input_csv = sys.argv[1]
    
    # Определяем выходной файл
    if len(sys.argv) >= 3:
        output_csv = sys.argv[2]
    else:
        # По умолчанию: перезаписываем исходный файл
        output_csv = input_csv
    
    sort_csv_by_address(input_csv, output_csv)


if __name__ == "__main__":
    main()