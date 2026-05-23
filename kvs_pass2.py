#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Второй проход КВС
- Собирает адреса всех приводящих меток (поддерживает несколько меток через запятую)
- Заменяет заглушки в уводящих адресах на реальные адреса
- Записывает рассчитанные значения в колонку 'рассчитанный_уводящий_адрес' (файловое смещение)
- Формирует команду с подставленными адресами в колонку 'команда_со_значениями' (виртуальный адрес)
- Пропускает заглушки, которые не найдены (возможно это константы)
- Выводит статистику по неразрешённым заглушкам
"""

import sys
import csv
from collections import Counter


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


def get_virtual_addresses(entries, headers):
    """
    Извлекает виртуальные адреса секций из заголовка CSV
    Возвращает (vaddr_text, vaddr_data)
    """
    vaddr_text = 0x401000
    vaddr_data = 0x402000
    
    try:
        source_idx = headers.index('исходная_команда')
        calc_target_idx = headers.index('рассчитанный_уводящий_адрес')
    except ValueError:
        return vaddr_text, vaddr_data
    
    for row in entries:
        source = row[source_idx].strip()
        calc_target = row[calc_target_idx].strip()
        
        if 'p_vaddr (text)' in source and calc_target:
            parts = calc_target.split('=')
            if len(parts) >= 2:
                addr_str = parts[1].strip()
                if addr_str.startswith('0x'):
                    vaddr_text = int(addr_str, 16)
        
        elif 'p_vaddr (data)' in source and calc_target:
            parts = calc_target.split('=')
            if len(parts) >= 2:
                addr_str = parts[1].strip()
                if addr_str.startswith('0x'):
                    vaddr_data = int(addr_str, 16)
    
    return vaddr_text, vaddr_data


def collect_labels(entries, headers, vaddr_text, vaddr_data):
    """
    Собирает адреса всех приводящих меток.
    Возвращает два словаря:
    - labels_file: имя метки -> файловое смещение
    - labels_virt: имя метки -> виртуальный адрес
    """
    labels_file = {}  # имя метки -> файловое смещение
    labels_virt = {}  # имя метки -> виртуальный адрес
    
    try:
        label_idx = headers.index('приводящая_метка')
        addr_idx = headers.index('адрес')
        segment_idx = headers.index('сегмент')
    except ValueError as e:
        print(f"Ошибка: не найдена нужная колонка в CSV: {e}")
        sys.exit(1)
    
    for row in entries:
        label_str = row[label_idx].strip()
        if label_str:
            addr_str = row[addr_idx].strip()
            if addr_str.startswith('0x'):
                file_addr = int(addr_str, 16)
                segment = row[segment_idx].strip()
                
                # Вычисляем виртуальный адрес
                if segment == '.text':
                    virt_addr = vaddr_text + (file_addr - 0x1000)
                elif segment == '.data':
                    virt_addr = vaddr_data + (file_addr - 0x2000)
                else:
                    virt_addr = file_addr
                
                # Разделяем несколько меток через запятую
                for label_name in label_str.split(','):
                    label_name = label_name.strip()
                    if label_name:
                        labels_file[label_name] = file_addr
                        labels_virt[label_name] = virt_addr
    
    return labels_file, labels_virt


def resolve_targets(entries, headers, labels_file, labels_virt):
    """
    Заменяет уводящие адреса-заглушки на реальные адреса
    - рассчитанный_уводящий_адрес: файловое смещение
    - команда_со_значениями: виртуальный адрес
    """
    try:
        target_idx = headers.index('уводящий_адрес')
        calc_target_idx = headers.index('рассчитанный_уводящий_адрес')
        source_idx = headers.index('исходная_команда')
        source_with_values_idx = headers.index('команда_со_значениями')
    except ValueError as e:
        print(f"Ошибка: не найдена нужная колонка в CSV: {e}")
        sys.exit(1)
    
    resolved = []  # (имя_метки, файловый_адрес, виртуальный_адрес)
    unresolved = []  # имя_метки
    
    for row in entries:
        target = row[target_idx].strip()
        
        if target and target.startswith('ЗАГЛУШКА '):
            label_name = target.replace('ЗАГЛУШКА ', '').strip()
            
            if label_name in labels_file:
                file_addr = labels_file[label_name]
                virt_addr = labels_virt[label_name]
                file_hex = f"0x{file_addr:08x}"
                virt_hex = f"0x{virt_addr:08x}"
                
                # Файловое смещение в рассчитанный_уводящий_адрес
                row[calc_target_idx] = file_hex
                resolved.append((label_name, file_addr, virt_addr))
                
                # Виртуальный адрес в команда_со_значениями
                source_cmd = row[source_idx].strip()
                if source_cmd:
                    cmd_with_addr = source_cmd.replace(label_name, virt_hex)
                    row[source_with_values_idx] = cmd_with_addr
            else:
                unresolved.append(label_name)
                row[calc_target_idx] = ""
    
    return resolved, unresolved


def save_csv(csv_file, headers, entries):
    """Сохраняет обновлённый CSV файл"""
    with open(csv_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f, delimiter=';')
        writer.writerow(headers)
        writer.writerows(entries)


def print_statistics(labels_count, resolved, unresolved, vaddr_text, vaddr_data):
    """Выводит статистику по разрешению меток"""
    print(f"\n--- Статистика разрешения меток ---")
    print(f"  Виртуальный адрес .text: 0x{vaddr_text:x}")
    print(f"  Виртуальный адрес .data: 0x{vaddr_data:x}")
    print(f"  Всего приводящих меток: {labels_count}")
    print(f"  Разрешено заглушек: {len(resolved)}")
    print(f"  Не разрешено заглушек (возможно константы): {len(unresolved)}")
    
    if resolved:
        unique_resolved = {}
        for name, file_addr, virt_addr in resolved:
            if name not in unique_resolved:
                unique_resolved[name] = (file_addr, virt_addr)
        
        print(f"\n--- Разрешённые заглушки (первые 20) ---")
        for i, (name, (file_addr, virt_addr)) in enumerate(list(unique_resolved.items())[:20]):
            print(f"    {name} -> файл:0x{file_addr:08x}, вирт:0x{virt_addr:08x}")
        if len(unique_resolved) > 20:
            print(f"    ... и ещё {len(unique_resolved) - 20}")
    
    if unresolved:
        unresolved_counts = Counter(unresolved)
        print(f"\n--- Неразрешённые заглушки (возможно константы) ---")
        for name, count in sorted(unresolved_counts.items(), key=lambda x: x[1], reverse=True)[:20]:
            print(f"    {name}: {count} раз(а)")
        if len(unresolved_counts) > 20:
            print(f"    ... и ещё {len(unresolved_counts) - 20} различных имён")


def main():
    if len(sys.argv) != 2:
        print("Использование: python kvs_pass2.py <входной.csv>")
        sys.exit(1)
    
    csv_file = sys.argv[1]
    
    print(f"\n=== Второй проход КВС ===")
    print(f"Чтение CSV: {csv_file}")
    
    headers, entries = read_csv(csv_file)
    
    vaddr_text, vaddr_data = get_virtual_addresses(entries, headers)
    print(f"Виртуальный адрес .text: 0x{vaddr_text:x}")
    print(f"Виртуальный адрес .data: 0x{vaddr_data:x}")
    
    print(f"\n--- Сбор приводящих меток ---")
    labels_file, labels_virt = collect_labels(entries, headers, vaddr_text, vaddr_data)
    print(f"Найдено приводящих меток: {len(labels_file)}")
    
    if labels_file:
        print(f"\n--- Примеры приводящих меток (первые 20) ---")
        for i, name in enumerate(list(labels_file.keys())[:20]):
            print(f"    {name} -> файл:0x{labels_file[name]:08x}, вирт:0x{labels_virt[name]:08x}")
        if len(labels_file) > 20:
            print(f"    ... и ещё {len(labels_file) - 20}")
    
    print(f"\n--- Разрешение уводящих адресов и формирование команд ---")
    resolved, unresolved = resolve_targets(entries, headers, labels_file, labels_virt)
    
    print_statistics(len(labels_file), resolved, unresolved, vaddr_text, vaddr_data)
    
    save_csv(csv_file, headers, entries)
    print(f"\nCSV сохранен: {csv_file}")


if __name__ == "__main__":
    main()