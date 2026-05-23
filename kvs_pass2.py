#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Второй проход КВС (упрощённый)
- Собирает адреса всех приводящих меток из колонки 'виртуальный_адрес'
- Заменяет заглушки в уводящих адресах на реальные адреса
- Записывает рассчитанные значения в колонку 'рассчитанный_уводящий_адрес' (файловое смещение)
- Формирует команду с подставленными виртуальными адресами в колонку 'команда_со_значениями'
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


def collect_labels(entries, headers):
    """
    Собирает адреса всех приводящих меток.
    Использует колонку 'виртуальный_адрес' для получения адреса метки.
    Возвращает словарь: имя метки -> виртуальный адрес
    """
    labels = {}
    
    try:
        label_idx = headers.index('приводящая_метка')
        virt_addr_idx = headers.index('виртуальный_адрес')
    except ValueError as e:
        print(f"Ошибка: не найдена нужная колонка в CSV: {e}")
        sys.exit(1)
    
    for row in entries:
        label_str = row[label_idx].strip()
        if label_str:
            virt_addr_str = row[virt_addr_idx].strip()
            if virt_addr_str.startswith('0x'):
                virt_addr = int(virt_addr_str, 16)
                
                for label_name in label_str.split(','):
                    label_name = label_name.strip()
                    if label_name:
                        labels[label_name] = virt_addr
    
    # Выводим статистику собранных меток
    print(f"\n{'='*80}")
    print(f"СОБРАННЫЕ ПРИВОДЯЩИЕ МЕТКИ (всего: {len(labels)})")
    print(f"{'='*80}")
    print(f"\n{'Имя метки':<35} {'Виртуальный адрес':<22}")
    print(f"{'-'*57}")
    
    for name in sorted(labels.keys()):
        virt_addr = labels[name]
        print(f"{name:<35} 0x{virt_addr:08x} ({virt_addr})")
    
    return labels


def resolve_targets(entries, headers, labels):
    """
    Заменяет уводящие адреса-заглушки на реальные адреса
    - рассчитанный_уводящий_адрес: файловое смещение (берём из колонки 'адрес')
    - команда_со_значениями: виртуальный адрес
    """
    try:
        target_idx = headers.index('уводящий_адрес')
        calc_target_idx = headers.index('рассчитанный_уводящий_адрес')
        source_idx = headers.index('исходная_команда')
        source_with_values_idx = headers.index('команда_со_значениями')
        addr_idx = headers.index('адрес')
    except ValueError as e:
        print(f"Ошибка: не найдена нужная колонка в CSV: {e}")
        sys.exit(1)
    
    resolved = []
    unresolved = []
    
    for row in entries:
        target = row[target_idx].strip()
        
        if target and target.startswith('ЗАГЛУШКА '):
            label_name = target.replace('ЗАГЛУШКА ', '').strip()
            
            if label_name in labels:
                virt_addr = labels[label_name]
                virt_hex = f"0x{virt_addr:08x}"
                
                # Файловое смещение берём из колонки 'адрес' текущей строки
                addr_str = row[addr_idx].strip()
                if addr_str.startswith('0x'):
                    file_addr = int(addr_str, 16)
                    file_hex = f"0x{file_addr:08x}"
                    row[calc_target_idx] = file_hex
                    resolved.append((label_name, file_addr, virt_addr))
                else:
                    row[calc_target_idx] = ""
                    resolved.append((label_name, 0, virt_addr))
                
                # Подставляем виртуальный адрес в команду
                source_cmd = row[source_idx].strip()
                if source_cmd:
                    cmd_with_addr = source_cmd.replace(label_name, virt_hex)
                    row[source_with_values_idx] = cmd_with_addr
            else:
                unresolved.append(label_name)
                row[calc_target_idx] = ""
    
    # Выводим статистику разрешённых заглушек
    print(f"\n{'='*80}")
    print(f"РАЗРЕШЁННЫЕ ЗАГЛУШКИ (всего: {len(resolved)})")
    print(f"{'='*80}")
    
    if resolved:
        unique_resolved = {}
        for name, file_addr, virt_addr in resolved:
            if name not in unique_resolved:
                unique_resolved[name] = (file_addr, virt_addr)
        
        print(f"\nУникальных меток: {len(unique_resolved)}")
        print(f"\n{'Имя метки':<35} {'Файловое смещение':<22} {'Виртуальный адрес':<22}")
        print(f"{'-'*79}")
        
        for name in sorted(unique_resolved.keys()):
            file_addr, virt_addr = unique_resolved[name]
            if file_addr:
                print(f"{name:<35} 0x{file_addr:08x} ({file_addr:<10}) 0x{virt_addr:08x} ({virt_addr})")
            else:
                print(f"{name:<35} {'(не известно)':<22} 0x{virt_addr:08x} ({virt_addr})")
    else:
        print("\n--- НЕТ РАЗРЕШЁННЫХ ЗАГЛУШЕК ---")
    
    # Выводим статистику неразрешённых заглушек
    print(f"\n{'='*80}")
    print(f"НЕРАЗРЕШЁННЫЕ ЗАГЛУШКИ (всего: {len(unresolved)})")
    print(f"{'='*80}")
    
    if unresolved:
        unresolved_counts = Counter(unresolved)
        print(f"\nУникальных неразрешённых имён: {len(unresolved_counts)}")
        print(f"\n{'Имя метки':<35} {'Количество вхождений':<20}")
        print(f"{'-'*55}")
        
        for name, count in sorted(unresolved_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"{name:<35} {count}")
    else:
        print("\n--- НЕТ НЕРАЗРЕШЁННЫХ ЗАГЛУШЕК ---")
    
    return resolved, unresolved


def save_csv(csv_file, headers, entries):
    """Сохраняет обновлённый CSV файл"""
    with open(csv_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f, delimiter=';')
        writer.writerow(headers)
        writer.writerows(entries)


def main():
    if len(sys.argv) != 2:
        print("Использование: python kvs_pass2.py <входной.csv>")
        sys.exit(1)
    
    csv_file = sys.argv[1]
    
    print(f"\n=== ВТОРОЙ ПРОХОД КВС (упрощённый) ===")
    print(f"Чтение CSV: {csv_file}")
    
    headers, entries = read_csv(csv_file)
    
    print(f"\n--- СБОР ПРИВОДЯЩИХ МЕТОК ---")
    labels = collect_labels(entries, headers)
    
    print(f"\n--- РАЗРЕШЕНИЕ УВОДЯЩИХ АДРЕСОВ ---")
    resolved, unresolved = resolve_targets(entries, headers, labels)
    
    print(f"\n{'='*80}")
    print(f"ОБЩАЯ СТАТИСТИКА")
    print(f"{'='*80}")
    print(f"  Приводящих меток в CSV: {len(labels)}")
    print(f"  Разрешено заглушек: {len(resolved)}")
    print(f"  Не разрешено заглушек: {len(unresolved)}")
    print(f"{'='*80}")
    
    save_csv(csv_file, headers, entries)
    print(f"\nCSV сохранён: {csv_file}")


if __name__ == "__main__":
    main()