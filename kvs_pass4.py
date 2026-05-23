#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Четвёртый проход КВС
- Перекодирует инструкции, используя подставленные значения
- Смотрит колонки 'команда_со_значениями' и 'рассчитанный_уводящий_адрес'
- Записывает перекодированные байты в колонку 'рассчитанный_байт'
"""

import sys
import csv
import struct

sys.path.insert(0, '.')
from kvs_data import PAGE_SIZE, text_vaddr_base, align_up
from kvs_encoder import encode_instruction

# ========== ГЛОБАЛЬНОЕ СОСТОЯНИЕ ==========
vaddr_text = text_vaddr_base
vaddr_data = None
vaddr_bnd = None

labels = {}  # имя метки -> адрес
label_sections = {}  # имя метки -> секция
symbols = {}  # имя константы -> значение


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


def parse_command(cmd_str):
    """Разбирает команду вида 'мнемоника операнд1, операнд2, ...'"""
    if not cmd_str:
        return None, []
    
    parts = cmd_str.split(' ', 1)
    mnemonic = parts[0]
    
    operands = []
    if len(parts) > 1 and parts[1]:
        # Разбираем операнды, разделённые запятыми
        operands = [op.strip() for op in parts[1].split(',')]
    
    return mnemonic, operands


def collect_labels_from_csv(entries, headers):
    """Собирает метки из CSV для перекодирования"""
    global labels, label_sections, vaddr_data, vaddr_bnd
    
    try:
        label_idx = headers.index('приводящая_метка')
        addr_idx = headers.index('адрес')
        segment_idx = headers.index('сегмент')
        byte_idx = headers.index('байт')
    except ValueError as e:
        print(f"Ошибка: не найдена нужная колонка в CSV: {e}")
        sys.exit(1)
    
    # Сначала нужно определить виртуальные адреса секций
    max_addr = 0
    for row in entries:
        addr_str = row[addr_idx].strip()
        if addr_str.startswith('0x'):
            addr = int(addr_str, 16)
            if addr > max_addr:
                max_addr = addr
            segment = row[segment_idx].strip()
            
            # Определяем vaddr_data по первому адресу в .data
            if segment == '.data' and vaddr_data is None:
                vaddr_data = addr
            # Определяем vaddr_bnd по первому адресу в .bss
            elif segment == '.bss' and vaddr_bnd is None:
                vaddr_bnd = addr
    
    if vaddr_data is None:
        vaddr_data = align_up(vaddr_text + max_addr, PAGE_SIZE)
    if vaddr_bnd is None:
        vaddr_bnd = align_up(vaddr_data + max_addr, PAGE_SIZE)
    
    # Собираем метки
    for row in entries:
        label_str = row[label_idx].strip()
        if label_str:
            addr_str = row[addr_idx].strip()
            if addr_str.startswith('0x'):
                addr = int(addr_str, 16)
                for label_name in label_str.split(','):
                    label_name = label_name.strip()
                    if label_name:
                        labels[label_name] = addr
                        # Определяем секцию по адресу
                        if addr >= vaddr_text and addr < vaddr_text + PAGE_SIZE:
                            label_sections[label_name] = '.text'
                        elif vaddr_data and addr >= vaddr_data and addr < vaddr_data + PAGE_SIZE:
                            label_sections[label_name] = '.data'
                        elif vaddr_bnd and addr >= vaddr_bnd:
                            label_sections[label_name] = '.bss'


def reencode_instructions(entries, headers):
    """Перекодирует инструкции, используя подставленные значения"""
    try:
        source_with_values_idx = headers.index('команда_со_значениями')
        calc_target_idx = headers.index('рассчитанный_уводящий_адрес')
        calc_byte_idx = headers.index('рассчитанный_байт')
        addr_idx = headers.index('адрес')
        segment_idx = headers.index('сегмент')
        byte_idx = headers.index('байт')
    except ValueError as e:
        print(f"Ошибка: не найдена нужная колонка в CSV: {e}")
        sys.exit(1)
    
    reencoded_count = 0
    error_count = 0
    
    # Проходим по всем строкам
    i = 0
    while i < len(entries):
        row = entries[i]
        addr_str = row[addr_idx].strip()
        if not addr_str.startswith('0x'):
            i += 1
            continue
        
        addr = int(addr_str, 16)
        segment = row[segment_idx].strip()
        
        # Проверяем, есть ли команда для перекодирования
        cmd = row[source_with_values_idx].strip()
        calc_target = row[calc_target_idx].strip()
        
        # Определяем, нужно ли перекодировать
        need_reencode = False
        
        if cmd:
            # Есть команда с подставленными константами
            need_reencode = True
        elif calc_target and calc_target.startswith('0x'):
            # Есть рассчитанный адрес для заглушки
            # Нужно взять исходную команду и подставить адрес
            source_idx = headers.index('исходная_команда')
            source = row[source_idx].strip()
            if source:
                # Заменяем ЗАГЛУШКА имя на реальный адрес
                target_addr = int(calc_target, 16)
                cmd = source.replace('ЗАГЛУШКА', '').strip()
                # Добавляем адрес как операнд
                cmd = f"{cmd} 0x{target_addr:08x}"
                need_reencode = True
        
        if need_reencode and cmd:
            try:
                mnemonic, operands = parse_command(cmd)
                if mnemonic:
                    # Вычисляем текущую позицию в секции
                    if segment == '.text':
                        current_pos = addr - vaddr_text
                    elif segment == '.data' and vaddr_data:
                        current_pos = addr - vaddr_data
                    else:
                        current_pos = 0
                    
                    # Кодируем инструкцию
                    encoded = encode_instruction(
                        mnemonic, operands, labels, label_sections, symbols,
                        vaddr_text, vaddr_data if vaddr_data else 0,
                        current_pos, vaddr_bnd if vaddr_bnd else 0
                    )
                    
                    # Записываем байты в колонку рассчитанный_байт
                    # Для много-байтовых инструкций записываем в последовательные строки
                    for j, byte in enumerate(encoded):
                        if i + j < len(entries):
                            entries[i + j][calc_byte_idx] = f"0x{byte:02x}"
                        else:
                            # Не хватает строк, создаём новую
                            # (в нормальной ситуации не должно происходить)
                            pass
                    
                    reencoded_count += 1
                    
                    # Пропускаем следующие строки, принадлежащие этой инструкции
                    # (обычно в CSV одна строка = один байт)
                    i += len(encoded)
                    continue
                    
            except Exception as e:
                print(f"Ошибка перекодирования '{cmd}': {e}")
                error_count += 1
                # Записываем INT3 как заглушку
                row[calc_byte_idx] = "0xcc"
                i += 1
        else:
            # Если нет команды для перекодирования, просто копируем исходный байт
            byte_str = row[byte_idx].strip()
            if byte_str.startswith('0x'):
                row[calc_byte_idx] = byte_str
            i += 1
    
    return reencoded_count, error_count


def save_csv(csv_file, headers, entries):
    """Сохраняет обновлённый CSV файл"""
    with open(csv_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f, delimiter=';')
        writer.writerow(headers)
        writer.writerows(entries)


def print_statistics(reencoded_count, error_count):
    """Выводит статистику перекодирования"""
    print(f"\n--- Статистика перекодирования ---")
    print(f"  Перекодировано инструкций: {reencoded_count}")
    if error_count:
        print(f"  Ошибок: {error_count}")


def main():
    if len(sys.argv) != 2:
        print("Использование: python kvs_pass4.py <входной.csv>")
        sys.exit(1)
    
    csv_file = sys.argv[1]
    
    print(f"\n=== Четвёртый проход КВС ===")
    print(f"Чтение CSV: {csv_file}")
    
    # Читаем CSV
    headers, entries = read_csv(csv_file)
    
    print(f"\n--- Сбор меток из CSV ---")
    collect_labels_from_csv(entries, headers)
    print(f"Найдено меток: {len(labels)}")
    
    print(f"\n--- Перекодирование инструкций ---")
    reencoded_count, error_count = reencode_instructions(entries, headers)
    
    print_statistics(reencoded_count, error_count)
    
    # Сохраняем результат
    save_csv(csv_file, headers, entries)
    print(f"\nCSV сохранен: {csv_file}")
    print(f"Колонка 'рассчитанный_байт' обновлена")


if __name__ == "__main__":
    main()