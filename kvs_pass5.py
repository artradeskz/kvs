#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Пятый проход КВС — генерация и добавление таблицы секций в CSV
Сканирует CSV, собирает информацию о секциях, обновляет ELF-заголовок
ПЕРЕСОЗДАЁТ ПРОГРАММНЫЕ ЗАГОЛОВКИ на основе реальных размеров секций
и добавляет таблицу секций в конец файла
ДОБАВЛЕНА НУЛЕВАЯ СЕКЦИЯ (индекс 0)
ДОБАВЛЕНА СЕКЦИЯ .comment со строкой "Сборщик КВС"
РАЗМЕЩЕНИЕ СЕКЦИЙ КАК В kvs_8.py
ПРАВИЛЬНЫЕ ИНДЕКСЫ В .shstrtab (с учётом наличия .bss)
"""

import sys
import csv
import struct

PAGE_SIZE = 0x1000
ELF_BASE_VADDR = 0x400000

DEBUG_PRINTS = True

def align_up(value, alignment):
    """Выравнивание вверх"""
    return ((value + alignment - 1) // alignment) * alignment


def analyze_csv(csv_file):
    """Анализирует CSV и собирает информацию о секциях"""
    
    sections = {
        '.text': {'start': None, 'end': None, 'size': 0, 'virt_start': None, 'virt_end': None},
        '.data': {'start': None, 'end': None, 'size': 0, 'virt_start': None, 'virt_end': None},
    }
    
    bss_blocks = []
    max_addr = 0
    
    with open(csv_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f, delimiter=';')
        
        for row in reader:
            seg = row['сегмент']
            addr_str = row['адрес']
            virt_addr_str = row['виртуальный_адрес']
            label = row['приводящая_метка']
            source = row['исходная_команда']
            
            if not seg:
                continue
            
            # Обновляем максимальный файловый адрес (только числовые адреса)
            if addr_str and addr_str != 'BSS' and addr_str != '':
                try:
                    addr = int(addr_str, 16)
                    if addr > max_addr:
                        max_addr = addr
                except:
                    pass
            
            # BSS секция (одна запись на блок)
            if seg == '.bss':
                if source and source.startswith('.резб'):
                    # Формат: ".резб 1048576"
                    parts = source.split()
                    if len(parts) >= 2:
                        size = int(parts[1])
                        virt_start = int(virt_addr_str, 16) if virt_addr_str else 0
                        bss_blocks.append({
                            'virt_start': virt_start,
                            'size': size,
                            'label': label,
                            'source': source
                        })
                continue
            
            # Обычные секции
            if addr_str == 'BSS' or addr_str == '':
                continue
            
            try:
                addr = int(addr_str, 16)
                virt_addr = int(virt_addr_str, 16)
            except:
                continue
            
            if seg == '.text':
                if sections['.text']['start'] is None:
                    sections['.text']['start'] = addr
                    sections['.text']['virt_start'] = virt_addr
                sections['.text']['end'] = addr
                sections['.text']['virt_end'] = virt_addr
                sections['.text']['size'] += 1
            
            elif seg == '.data':
                if sections['.data']['start'] is None:
                    sections['.data']['start'] = addr
                    sections['.data']['virt_start'] = virt_addr
                sections['.data']['end'] = addr
                sections['.data']['virt_end'] = virt_addr
                sections['.data']['size'] += 1
    
    # Пересчёт размеров секций из адресов
    if sections['.text']['start'] and sections['.text']['end']:
        sections['.text']['size'] = sections['.text']['end'] - sections['.text']['start'] + 1
    
    if sections['.data']['start'] and sections['.data']['end']:
        sections['.data']['size'] = sections['.data']['end'] - sections['.data']['start'] + 1
    
    # Вычисляем общий размер BSS и начальный виртуальный адрес
    bss_total_size = sum(block['size'] for block in bss_blocks)
    bss_start_vaddr = min((block['virt_start'] for block in bss_blocks), default=0)
    
    return sections, bss_blocks, max_addr, bss_total_size, bss_start_vaddr


def generate_comment_data():
    """Генерирует данные для секции .comment (UTF-8 строка 'Сборщик КВС' с нуль-терминатором)"""
    comment_str = 'Сборщик КВС'
    return comment_str.encode('utf-8') + b'\x00'


def generate_shstrtab_binary(has_bss):
    """Генерирует бинарную таблицу имён секций (как в kvs_8.py)"""
    if has_bss:
        names = ['', '.text', '.data', '.bss', '.comment', '.shstrtab']
    else:
        names = ['', '.text', '.data', '.comment', '.shstrtab']
    
    result = b''
    for name in names:
        result += name.encode('ascii') + b'\x00'
    
    return result


def create_null_section_entry(shdr_offset):
    """Создаёт нулевую секцию (индекс 0) — все поля нулевые"""
    entries = []
    for j in range(64):
        byte_val = 0x01 if j == 48 else 0x00  # sh_addralign = 1
        entries.append({
            'сегмент': '.shdr',
            'адрес': f"0x{shdr_offset + j:08x}",
            'виртуальный_адрес': '0x00000000',
            'байт': f"0x{byte_val:02x}",
            'приводящая_метка': 'NULL' if j == 0 else '',
            'уводящий_адрес': '',
            'исходная_команда': '.shdr NULL' if j == 0 else '',
            'команда_со_значениями': '',
            'рассчитанный_уводящий_адрес': '',
            'рассчитанный_байт': f"0x{byte_val:02x}"
        })
    return entries


def create_section_table_entries(sections, has_bss, shdr_offset, shstrtab_offset, 
                                  comment_offset, comment_size, shstrtab_data,
                                  bss_start_vaddr, bss_total_size):
    """Создаёт записи таблицы секций для CSV (с нулевой секцией, .comment и .shstrtab)"""
    
    if DEBUG_PRINTS:
        print("\n[DEBUG] create_section_table_entries")
        print(f"  has_bss = {has_bss}")
        print(f"  bss_start_vaddr = 0x{bss_start_vaddr:x}")
        print(f"  bss_total_size = {bss_total_size}")
        print(f"  shdr_offset = 0x{shdr_offset:x}")
        print(f"  shstrtab_offset = 0x{shstrtab_offset:x}")
        print(f"  comment_offset = 0x{comment_offset:x}")
        print(f"  comment_size = {comment_size}")
    
    entries = []
    
    # Нулевая секция
    null_entries = create_null_section_entry(shdr_offset)
    entries.extend(null_entries)
    
    if DEBUG_PRINTS:
        print(f"  Нулевая секция: {len(null_entries)} байт по адресу 0x{shdr_offset:x}")
    
    next_offset = shdr_offset + 64
    
    if DEBUG_PRINTS:
        print(f"  next_offset = 0x{next_offset:x}")
    
    # Индексы в .shstrtab
    if has_bss:
        idx_text = 1
        idx_data = 7
        idx_bss = 13
        idx_comment = 18
        idx_shstrtab = 27 # это харкод, если поменяю название сборщика - придется менять
    else:
        idx_text = 1
        idx_data = 7
        idx_comment = 13
        idx_shstrtab = 22
    
    if DEBUG_PRINTS:
        print(f"  Индексы в .shstrtab: text={idx_text}, data={idx_data}, bss={idx_bss if has_bss else 'N/A'}, comment={idx_comment}, shstrtab={idx_shstrtab}")
    
    # 1. .text
    header_text = struct.pack('<IIQQQQIIQQ',
        idx_text, 1, 6,
        sections['.text']['virt_start'],
        sections['.text']['start'],
        sections['.text']['size'],
        0, 0, 16, 0)
    
    # 2. .data
    header_data = struct.pack('<IIQQQQIIQQ',
        idx_data, 1, 3,
        sections['.data']['virt_start'],
        sections['.data']['start'],
        sections['.data']['size'],
        0, 0, 8, 0)
    
    headers = [header_text, header_data]
    header_names = ['.text', '.data']
    
    # 3. .bss (если есть)
    if has_bss and bss_total_size > 0:
        # SHT_NOBITS = 8, SHF_WRITE|SHF_ALLOC = 3
        header_bss = struct.pack('<IIQQQQIIQQ',
            idx_bss, 8, 3,
            bss_start_vaddr,   # sh_addr
            0,                  # sh_offset (для NOBITS неважно)
            bss_total_size,     # sh_size
            0, 0, 16, 0)
        headers.append(header_bss)
        header_names.append('.bss')
        if DEBUG_PRINTS:
            print(f"  Заголовок .bss: addr=0x{bss_start_vaddr:x}, size={bss_total_size}")
    
    # 4. .comment
    header_comment = struct.pack('<IIQQQQIIQQ',
        idx_comment, 1, 0,
        0, comment_offset, comment_size,
        0, 0, 1, 0)
    headers.append(header_comment)
    header_names.append('.comment')
    
    # 5. .shstrtab
    shstrtab_size = len(shstrtab_data)
    header_shstrtab = struct.pack('<IIQQQQIIQQ',
        idx_shstrtab, 3, 0,
        0, shstrtab_offset, shstrtab_size,
        0, 0, 1, 0)
    headers.append(header_shstrtab)
    header_names.append('.shstrtab')
    
    # Записываем заголовки секций
    if DEBUG_PRINTS:
        print(f"\n  Запись заголовков секций в CSV:")
    
    for i, header in enumerate(headers):
        base_addr = next_offset + i * 64
        if DEBUG_PRINTS:
            print(f"    Секция {i+1}: {header_names[i]} по адресу 0x{base_addr:x}")
        for j, byte in enumerate(header):
            entries.append({
                'сегмент': '.shdr',
                'адрес': f"0x{base_addr + j:08x}",
                'виртуальный_адрес': '0x00000000',
                'байт': f"0x{byte:02x}",
                'приводящая_метка': header_names[i] if j == 0 else '',
                'уводящий_адрес': '',
                'исходная_команда': f'.shdr {header_names[i]}' if j == 0 else '',
                'команда_со_значениями': '',
                'рассчитанный_уводящий_адрес': '',
                'рассчитанный_байт': f"0x{byte:02x}"
            })
    
    if DEBUG_PRINTS:
        print(f"\n  Всего заголовков: {len(headers)}")
        print(f"  Возвращаем секций: {len(headers) + 1} (включая NULL)")
    
    return entries, len(headers) + 1


def regenerate_program_headers_in_csv(csv_file, sections, bss_total_size, text_offset, data_offset):
    """Обновляет программные заголовки по адресу, вставляет новые при необходимости"""
    
    # Читаем CSV
    with open(csv_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f, delimiter=';')
        fieldnames = reader.fieldnames
        rows = list(reader)
    
    def get_addr_num(row):
        addr_str = row.get('адрес', '')
        if addr_str and addr_str != 'BSS' and addr_str.startswith('0x'):
            try:
                return int(addr_str, 16)
            except:
                return None
        return None
    
    addr_to_row = {}
    rows_without_addr = []
    
    for row in rows:
        addr = get_addr_num(row)
        if addr is not None:
            addr_to_row[addr] = row
        else:
            rows_without_addr.append(row)
    
    text_size = sections['.text']['size']
    data_size = sections['.data']['size']
    vaddr_text = sections['.text']['virt_start']
    vaddr_data = sections['.data']['virt_start']
    text_memsz = align_up(text_size, PAGE_SIZE)
    data_memsz = align_up(data_size + bss_total_size, PAGE_SIZE)
    
    new_entries = []
    
    header_defs = [
        # PHDR 0: ELF headers (R)
        (0x40, 0x01, 'I', 'p_type = 0x1'),
        (0x44, 0x04, 'I', 'p_flags = 0x4'),
        (0x48, 0x00, 'Q', 'p_offset = 0x0'),
        (0x50, ELF_BASE_VADDR, 'Q', 'p_vaddr = 0x400000'),
        (0x58, ELF_BASE_VADDR, 'Q', 'p_paddr = 0x400000'),
        (0x60, 0xe8, 'Q', 'p_filesz = 232'),
        (0x68, align_up(0xe8, PAGE_SIZE), 'Q', 'p_memsz = 4096'),
        (0x70, PAGE_SIZE, 'Q', 'p_align = 0x1000'),
        
        # PHDR 1: .text (R E)
        (0x78, 0x01, 'I', 'p_type = 0x1'),
        (0x7c, 0x05, 'I', 'p_flags = 0x5'),
        (0x80, text_offset, 'Q', f'p_offset = 0x{text_offset:x}'),
        (0x88, vaddr_text, 'Q', f'p_vaddr = 0x{vaddr_text:x}'),
        (0x90, vaddr_text, 'Q', f'p_paddr = 0x{vaddr_text:x}'),
        (0x98, text_size, 'Q', f'p_filesz = {text_size}'),
        (0xa0, text_memsz, 'Q', f'p_memsz = {text_memsz}'),
        (0xa8, PAGE_SIZE, 'Q', 'p_align = 0x1000'),
        
        # PHDR 2: .data + .bss (RW)
        (0xb0, 0x01, 'I', 'p_type = 0x1'),
        (0xb4, 0x06, 'I', 'p_flags = 0x6'),
        (0xb8, data_offset, 'Q', f'p_offset = 0x{data_offset:x}'),
        (0xc0, vaddr_data, 'Q', f'p_vaddr = 0x{vaddr_data:x}'),
        (0xc8, vaddr_data, 'Q', f'p_paddr = 0x{vaddr_data:x}'),
        (0xd0, data_size, 'Q', f'p_filesz = {data_size}'),
        (0xd8, data_memsz, 'Q', f'p_memsz = {data_memsz}'),
        (0xe0, PAGE_SIZE, 'Q', 'p_align = 0x1000'),
    ]
    
    for addr, value, pack_type, command in header_defs:
        if pack_type == 'I':
            bytes_data = struct.pack('<I', value)
        else:
            bytes_data = struct.pack('<Q', value)
        
        for i, byte in enumerate(bytes_data):
            current_addr = addr + i
            new_row = {
                'сегмент': '.header',
                'адрес': f"0x{current_addr:08x}",
                'виртуальный_адрес': f"0x{current_addr:08x}",
                'байт': f"0x{byte:02x}",
                'приводящая_метка': '',
                'уводящий_адрес': '',
                'исходная_команда': command if i == 0 else '',
                'команда_со_значениями': '',
                'рассчитанный_уводящий_адрес': '',
                'рассчитанный_байт': f"0x{byte:02x}"
            }
            new_entries.append((current_addr, new_row))
    
    for addr, new_row in new_entries:
        addr_to_row[addr] = new_row
    
    sorted_addrs = sorted(addr_to_row.keys())
    
    final_rows = []
    for addr in sorted_addrs:
        final_rows.append(addr_to_row[addr])
    final_rows.extend(rows_without_addr)
    
    with open(csv_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, delimiter=';', restval='')
        writer.writeheader()
        writer.writerows(final_rows)
    
    print(f"✅ Программные заголовки обновлены в {csv_file}")
    print(f"   Обновлено/добавлено записей: {len(new_entries)}")
    print(f"   Всего записей с адресами: {len(sorted_addrs)}")


def update_elf_header_in_csv(csv_file, e_shoff, e_shnum, e_shentsize, e_shstrndx):
    """Обновляет ELF-заголовок в CSV файле"""
    
    rows = []
    with open(csv_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f, delimiter=';')
        fieldnames = reader.fieldnames
        for row in reader:
            rows.append(row)
    
    # e_shoff
    shoff_bytes = struct.pack('<Q', e_shoff)
    for i in range(8):
        addr = f"0x{0x28 + i:08x}"
        for row in rows:
            if row['адрес'] == addr:
                row['рассчитанный_байт'] = f"0x{shoff_bytes[i]:02x}"
                row['байт'] = f"0x{shoff_bytes[i]:02x}"
                row['исходная_команда'] = f"e_shoff = 0x{e_shoff:x}"
    
    # e_shnum
    shnum_bytes = struct.pack('<H', e_shnum)
    for i in range(2):
        addr = f"0x{0x3c + i:08x}"
        for row in rows:
            if row['адрес'] == addr:
                row['рассчитанный_байт'] = f"0x{shnum_bytes[i]:02x}"
                row['байт'] = f"0x{shnum_bytes[i]:02x}"
                row['исходная_команда'] = f"e_shnum = {e_shnum}"
    
    # e_shentsize
    shentsize_bytes = struct.pack('<H', e_shentsize)
    for i in range(2):
        addr = f"0x{0x3a + i:08x}"
        for row in rows:
            if row['адрес'] == addr:
                row['рассчитанный_байт'] = f"0x{shentsize_bytes[i]:02x}"
                row['байт'] = f"0x{shentsize_bytes[i]:02x}"
                row['исходная_команда'] = f"e_shentsize = {e_shentsize}"
    
    # e_shstrndx
    shstrndx_bytes = struct.pack('<H', e_shstrndx)
    for i in range(2):
        addr = f"0x{0x3e + i:08x}"
        for row in rows:
            if row['адрес'] == addr:
                row['рассчитанный_байт'] = f"0x{shstrndx_bytes[i]:02x}"
                row['байт'] = f"0x{shstrndx_bytes[i]:02x}"
                row['исходная_команда'] = f"e_shstrndx = {e_shstrndx}"
    
    # e_phnum
    phnum_bytes = struct.pack('<H', 3)
    for i in range(2):
        addr = f"0x{0x38 + i:08x}"
        for row in rows:
            if row['адрес'] == addr:
                row['рассчитанный_байт'] = f"0x{phnum_bytes[i]:02x}"
                row['байт'] = f"0x{phnum_bytes[i]:02x}"
                row['исходная_команда'] = f"e_phnum = 3"
    
    # e_phoff
    phoff_bytes = struct.pack('<Q', 0x40)
    for i in range(8):
        addr = f"0x{0x20 + i:08x}"
        for row in rows:
            if row['адрес'] == addr:
                row['рассчитанный_байт'] = f"0x{phoff_bytes[i]:02x}"
                row['байт'] = f"0x{phoff_bytes[i]:02x}"
                row['исходная_команда'] = f"e_phoff = 0x40"
    
    with open(csv_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, delimiter=';', restval='')
        writer.writeheader()
        writer.writerows(rows)
    
    print(f"✅ ELF-заголовок обновлён в {csv_file}")
    print(f"   e_shoff = 0x{e_shoff:x}")
    print(f"   e_shnum = {e_shnum}")
    print(f"   e_shentsize = {e_shentsize}")
    print(f"   e_shstrndx = {e_shstrndx}")


def merge_csv_with_section_table(csv_file, section_entries, comment_entries, shstrtab_entries):
    """Добавляет записи таблицы секций, .comment и .shstrtab в конец CSV файла"""
    
    with open(csv_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f, delimiter=';')
        fieldnames = reader.fieldnames
        rows = list(reader)
    
    existing_addrs = set()
    for row in rows:
        addr = row['адрес']
        if addr and addr != 'BSS':
            existing_addrs.add(addr)
    
    new_count = 0
    for entry in section_entries:
        if entry['адрес'] not in existing_addrs:
            rows.append(entry)
            existing_addrs.add(entry['адрес'])
            new_count += 1
    
    for entry in comment_entries:
        if entry['адрес'] not in existing_addrs:
            rows.append(entry)
            existing_addrs.add(entry['адрес'])
            new_count += 1
    
    for entry in shstrtab_entries:
        if entry['адрес'] not in existing_addrs:
            rows.append(entry)
            existing_addrs.add(entry['адрес'])
            new_count += 1
    
    print(f"   Добавлено {new_count} новых записей")
    
    with open(csv_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, delimiter=';', restval='')
        writer.writeheader()
        writer.writerows(rows)


def add_comment_data(comment_offset):
    """Создаёт записи для данных .comment"""
    entries = []
    comment_data = generate_comment_data()
    
    for j, byte in enumerate(comment_data):
        entries.append({
            'сегмент': '.comment',
            'адрес': f"0x{comment_offset + j:08x}",
            'виртуальный_адрес': '0x00000000',
            'байт': f"0x{byte:02x}",
            'приводящая_метка': 'Сборщик КВС' if j == 0 else '',
            'уводящий_адрес': '',
            'исходная_команда': '.comment byte' if j == 0 else '',
            'команда_со_значениями': '',
            'рассчитанный_уводящий_адрес': '',
            'рассчитанный_байт': f"0x{byte:02x}"
        })
    
    return entries


def add_shstrtab_data(shstrtab_offset, shstrtab_data):
    """Создаёт записи для данных .shstrtab"""
    entries = []
    
    for j, byte in enumerate(shstrtab_data):
        entries.append({
            'сегмент': '.shstrtab',
            'адрес': f"0x{shstrtab_offset + j:08x}",
            'виртуальный_адрес': '0x00000000',
            'байт': f"0x{byte:02x}",
            'приводящая_метка': '',
            'уводящий_адрес': '',
            'исходная_команда': '.shstrtab byte' if j == 0 else '',
            'команда_со_значениями': '',
            'рассчитанный_уводящий_адрес': '',
            'рассчитанный_байт': f"0x{byte:02x}"
        })
    
    return entries


def print_section_info(sections, has_bss, max_addr, bss_total_size, bss_start_vaddr):
    """Выводит основную информацию о секциях"""
    
    print("\n" + "="*60)
    print("ДИАГНОСТИКА ПЯТОГО ПРОХОДА")
    print("="*60)
    
    if sections['.text']['start']:
        print(f"\n📦 Секция .text:")
        print(f"   Файловое смещение: 0x{sections['.text']['start']:08x} - 0x{sections['.text']['end']:08x}")
        print(f"   Виртуальный адрес: 0x{sections['.text']['virt_start']:08x} - 0x{sections['.text']['virt_end']:08x}")
        print(f"   Размер: {sections['.text']['size']} байт")
    
    if sections['.data']['start']:
        print(f"\n📦 Секция .data:")
        print(f"   Файловое смещение: 0x{sections['.data']['start']:08x} - 0x{sections['.data']['end']:08x}")
        print(f"   Виртуальный адрес: 0x{sections['.data']['virt_start']:08x} - 0x{sections['.data']['virt_end']:08x}")
        print(f"   Размер: {sections['.data']['size']} байт")
    
    if has_bss:
        print(f"\n📦 Секция .bnd (BSS):")
        print(f"   Виртуальный адрес: 0x{bss_start_vaddr:08x}")
        print(f"   Размер: {bss_total_size} байт")
    else:
        print(f"\n📦 Секция .bnd (BSS):")
        print(f"   Нет BSS-блоков")
    
    print(f"\n📍 Максимальный файловый адрес: 0x{max_addr:08x}")

def main():
    if len(sys.argv) != 2:
        print("Использование: python kvs_pass5.py <файл.csv>")
        sys.exit(1)
    
    csv_file = sys.argv[1]
    
    print(f"\n📊 Анализ CSV: {csv_file}")
    
    sections, bss_blocks, max_addr, bss_total_size, bss_start_vaddr = analyze_csv(csv_file)
    has_bss = bss_total_size > 0
    print_section_info(sections, has_bss, max_addr, bss_total_size, bss_start_vaddr)
    
    text_offset = sections['.text']['start']
    data_offset = sections['.data']['start']
    text_size = sections['.text']['size']
    data_size = sections['.data']['size']
    
    comment_data = generate_comment_data()
    comment_size = len(comment_data)
    
    comment_offset = data_offset + data_size
    print(f"   comment_offset = 0x{comment_offset:x}")
    
    shstrtab_data = generate_shstrtab_binary(has_bss)
    shstrtab_size = len(shstrtab_data)
    shstrtab_offset = align_up(comment_offset + comment_size, 8)
    print(f"   shstrtab_offset = 0x{shstrtab_offset:x}")
    print(f"   shstrtab_size = {shstrtab_size}")
    
    num_sections = 5
    if has_bss:
        num_sections += 1
    
    shdr_offset = align_up(shstrtab_offset + shstrtab_size, 16)
    print(f"   shdr_offset = 0x{shdr_offset:x}")
    
    print(f"\n📍 Размещение секций (как в kvs_8.py):")
    print(f"   .data: 0x{data_offset:08x}")
    print(f"   .comment: 0x{comment_offset:08x} (размер {comment_size} байт)")
    print(f"   .shstrtab: 0x{shstrtab_offset:08x} (размер {shstrtab_size} байт)")
    print(f"   Таблица секций: 0x{shdr_offset:08x}")
    print(f"   Количество секций: {num_sections}")
    print(f"   Наличие BSS: {has_bss}")
    
    # === НОВЫЙ КОД: обновляем max_addr ===
    max_addr = max(max_addr, comment_offset + comment_size - 1)
    max_addr = max(max_addr, shstrtab_offset + shstrtab_size - 1)
    max_addr = max(max_addr, shdr_offset + (num_sections * 64) - 1)
    print(f"\n📍 Обновлённый максимальный файловый адрес: 0x{max_addr:08x}")
    # === КОНЕЦ НОВОГО КОДА ===
    
    # Обновляем программные заголовки с учётом BSS
    regenerate_program_headers_in_csv(csv_file, sections, bss_total_size, text_offset, data_offset)
    
    # Создаём записи таблицы секций
    entries, num_headers = create_section_table_entries(
        sections, has_bss, shdr_offset, shstrtab_offset, comment_offset, comment_size, 
        shstrtab_data, bss_start_vaddr, bss_total_size
    )
    
    comment_entries = add_comment_data(comment_offset)
    shstrtab_entries = add_shstrtab_data(shstrtab_offset, shstrtab_data)
    
    e_shoff = shdr_offset
    e_shnum = num_headers
    e_shentsize = 64
    e_shstrndx = num_headers - 1
    
    print(f"\n📝 Обновление ELF-заголовка:")
    print(f"   e_shoff = 0x{e_shoff:08x}")
    print(f"   e_shnum = {e_shnum}")
    print(f"   e_shentsize = {e_shentsize}")
    print(f"   e_shstrndx = {e_shstrndx}")
    
    update_elf_header_in_csv(csv_file, e_shoff, e_shnum, e_shentsize, e_shstrndx)
    merge_csv_with_section_table(csv_file, entries, comment_entries, shstrtab_entries)
    
    print(f"\n💾 Таблица секций добавлена в {csv_file}")
    print(f"   Добавлено {len(entries)} записей заголовков")
    print(f"   Добавлено {len(comment_entries)} записей .comment")
    print(f"   Добавлено {len(shstrtab_entries)} записей .shstrtab")
    print(f"\n✅ Готово! Размещение секций как в kvs_8.py:")
    print(f"   .comment сразу после .data")
    print(f"   .shstrtab выровнен на 8 байт")
    print(f"   Таблица секций выровнена на 16 байт")
    if has_bss:
        print(f"   BSS присутствует, размер {bss_total_size} байт, адрес 0x{bss_start_vaddr:x}")

if __name__ == "__main__":
    main()