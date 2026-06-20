#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Четвёртый проход КВС
- Перекодирует инструкции, используя подставленные значения
- Смотрит колонку 'команда_со_значениями'
- Записывает перекодированные байты в колонку 'рассчитанный_байт'
- Использует виртуальные адреса из CSV для вычисления смещений
"""

import sys
import csv

sys.path.insert(0, '.')
from kvs_data import PAGE_SIZE, text_vaddr_base, align_up
from kvs_encoder import encode_instruction

# ========== ГЛОБАЛЬНОЕ СОСТОЯНИЕ ==========
vaddr_text = None      # будет прочитано из CSV
vaddr_data = None      # будет прочитано из CSV
vaddr_bnd = None       # будет прочитано из CSV

labels = {}
label_sections = {}
symbols = {}


def read_csv(csv_file):
    entries = []
    headers = []
    
    with open(csv_file, 'r', encoding='utf-8') as f:
        reader = csv.reader(f, delimiter=';')
        headers = next(reader)
        for row in reader:
            entries.append(row)
    
    return headers, entries


def parse_command(cmd_str):
    if not cmd_str:
        return None, []
    
    parts = cmd_str.split(' ', 1)
    mnemonic = parts[0]
    
    operands = []
    if len(parts) > 1 and parts[1]:
        operands = [op.strip() for op in parts[1].split(',')]
    
    return mnemonic, operands


def detect_section_addresses(entries, headers, log_file):
    """
    Определяет виртуальные адреса секций из CSV.
    """
    global vaddr_text, vaddr_data, vaddr_bnd
    
    try:
        segment_idx = headers.index('сегмент')
        virt_addr_idx = headers.index('виртуальный_адрес')
    except ValueError as e:
        print(f"Ошибка: не найдена нужная колонка в CSV: {e}")
        sys.exit(1)
    
    found_text = False
    found_data = False
    found_bnd = False
    
    for row in entries:
        segment = row[segment_idx].strip()
        virt_addr_str = row[virt_addr_idx].strip()
        
        if not virt_addr_str.startswith('0x'):
            continue
        
        virt_addr = int(virt_addr_str, 16)
        
        if segment == '.text' and not found_text:
            vaddr_text = virt_addr
            found_text = True
            log_file.write(f"  .text: 0x{vaddr_text:x}\n")
        
        elif segment == '.data' and not found_data:
            vaddr_data = virt_addr
            found_data = True
            log_file.write(f"  .data: 0x{vaddr_data:x}\n")
        
        elif segment == '.bss' and not found_bnd:
            vaddr_bnd = virt_addr
            found_bnd = True
            log_file.write(f"  .bss: 0x{vaddr_bnd:x}\n")
    
    # Проверяем, что все нужные секции найдены
    if not found_text:
        print("  Ошибка: секция .text не найдена в CSV")
        sys.exit(1)
    
    if not found_data:
        log_file.write("  Предупреждение: секция .data не найдена в CSV, используем 0x402000\n")
        vaddr_data = 0x402000  # fallback


def collect_labels_from_csv(entries, headers, log_file):
    """
    Собирает метки из CSV, используя колонку 'виртуальный_адрес'
    """
    global labels, label_sections
    
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
                        label_sections[label_name] = ''
    
    log_file.write(f"Найдено меток: {len(labels)}\n")


def reencode_instructions(entries, headers, log_file):
    try:
        source_with_values_idx = headers.index('команда_со_значениями')
        calc_byte_idx = headers.index('рассчитанный_байт')
        addr_idx = headers.index('адрес')
        virt_addr_idx = headers.index('виртуальный_адрес')
        byte_idx = headers.index('байт')
        segment_idx = headers.index('сегмент')
    except ValueError as e:
        print(f"Ошибка: не найдена нужная колонка в CSV: {e}")
        sys.exit(1)
    
    reencoded_count = 0
    error_count = 0
    
    i = 0
    while i < len(entries):
        row = entries[i]
        addr_str = row[addr_idx].strip()
        if not addr_str.startswith('0x'):
            i += 1
            continue
        
        file_addr = int(addr_str, 16)
        
        # Берём виртуальный адрес инструкции из CSV
        virt_addr_str = row[virt_addr_idx].strip()
        if virt_addr_str.startswith('0x'):
            instr_virt_addr = int(virt_addr_str, 16)
        else:
            instr_virt_addr = file_addr
        
        cmd = row[source_with_values_idx].strip()
        
        if cmd:
            try:
                mnemonic, operands = parse_command(cmd)
                if mnemonic:
                    # Для отладки: записываем в лог все инструкции переместить_имм
                    if mnemonic == 'переместить_имм' and operands and '0x00403014' in cmd:
                        log_file.write(f"\nDEBUG MOV:\n")
                        log_file.write(f"  Адрес в CSV: 0x{file_addr:08x}\n")
                        log_file.write(f"  Команда: {cmd}\n")
                        log_file.write(f"  Операнды: {operands}\n")
                    
                    # Вычисляем current_pos как смещение в секции
                    section = row[segment_idx].strip()
                    
                    if section == '.text':
                        current_pos = instr_virt_addr - vaddr_text
                    elif section == '.data':
                        current_pos = instr_virt_addr - vaddr_data
                    elif section == '.bss':
                        current_pos = instr_virt_addr - vaddr_bnd if vaddr_bnd else 0
                    else:
                        # Fallback: определяем по диапазону адресов - ФУФЛО, УБРАТЬ
                        if vaddr_text and 0x401000 <= instr_virt_addr < 0x402000:
                            current_pos = instr_virt_addr - vaddr_text
                        elif vaddr_data and 0x402000 <= instr_virt_addr < 0x403000:
                            current_pos = instr_virt_addr - vaddr_data
                        else:
                            current_pos = instr_virt_addr
                    
                    encoded = encode_instruction(
                        mnemonic, operands, labels, label_sections, symbols,
                        vaddr_text, vaddr_data if vaddr_data else 0,
                        current_pos, vaddr_bnd if vaddr_bnd else 0
                    )
                    
                    # Для отладки: записываем результат
                    if mnemonic == 'переместить_имм' and operands and '0x00403014' in cmd:
                        log_file.write(f"  Закодировано: {[f'0x{b:02x}' for b in encoded]}\n")
                        log_file.write(f"  Длина: {len(encoded)} байт\n")
                    
                    for j, byte in enumerate(encoded):
                        if i + j < len(entries):
                            entries[i + j][calc_byte_idx] = f"0x{byte:02x}"
                    
                    reencoded_count += 1
                    i += len(encoded)
                    continue
                    
            except Exception as e:
                log_file.write(f"\n=== ОШИБКА ===\n")
                log_file.write(f"  Команда: {cmd}\n")
                log_file.write(f"  Мнемоника: {mnemonic if 'mnemonic' in locals() else '?'}\n")
                log_file.write(f"  Ошибка: {e}\n")
                error_count += 1
                row[calc_byte_idx] = "0xcc"
                i += 1
        else:
            # Если нет команды, копируем исходный байт
            byte_str = row[byte_idx].strip()
            if byte_str.startswith('0x'):
                row[calc_byte_idx] = byte_str
            i += 1
    
    return reencoded_count, error_count


def save_csv(csv_file, headers, entries):
    with open(csv_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f, delimiter=';')
        writer.writerow(headers)
        writer.writerows(entries)


def print_statistics(reencoded_count, error_count, labels_count):
    print(f"\n--- Статистика перекодирования ---")
    print(f"  Меток в словаре: {labels_count}")
    print(f"  Перекодировано инструкций: {reencoded_count}")
    if error_count:
        print(f"  Ошибок: {error_count}")
    else:
        print(f"  Ошибок: нет")


def main():
    if len(sys.argv) != 2:
        print("Использование: python kvs_pass4.py <входной.csv>")
        sys.exit(1)
    
    csv_file = sys.argv[1]
    log_file_name = csv_file.replace('.csv', '_pass4.log')
    
    print(f"\n=== Четвёртый проход КВС ===")
    print(f"Чтение CSV: {csv_file}")
    
    with open(log_file_name, 'w', encoding='utf-8') as log_file:
        log_file.write(f"=== Четвёртый проход КВС ===\n")
        log_file.write(f"CSV: {csv_file}\n\n")
        
        headers, entries = read_csv(csv_file)
        
        log_file.write(f"--- Определение адресов секций из CSV ---\n")
        detect_section_addresses(entries, headers, log_file)
        
        log_file.write(f"\n--- Сбор меток из CSV ---\n")
        collect_labels_from_csv(entries, headers, log_file)
        
        log_file.write(f"\n--- Перекодирование инструкций ---\n")
        reencoded_count, error_count = reencode_instructions(entries, headers, log_file)
        
        log_file.write(f"\n--- Статистика ---\n")
        log_file.write(f"  Меток в словаре: {len(labels)}\n")
        log_file.write(f"  Перекодировано инструкций: {reencoded_count}\n")
        log_file.write(f"  Ошибок: {error_count}\n")
    
    print_statistics(reencoded_count, error_count, len(labels))
    
    save_csv(csv_file, headers, entries)
    print(f"\nCSV сохранён: {csv_file}")
    print(f"Лог сохранён: {log_file_name}")


if __name__ == "__main__":
    main()