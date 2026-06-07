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
            
            # BSS секция
            if seg == '.bss':
                if source and source.startswith('.резб'):
                    size = int(source.split()[1])
                    virt_start = int(virt_addr_str, 16)
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
    
    return sections, bss_blocks, max_addr


def generate_comment_data():
    """Генерирует данные для секции .comment (UTF-8 строка 'Сборщик КВС' с нуль-терминатором)"""
    comment_str = 'Сборщик КВС'
    return comment_str.encode('utf-8') + b'\x00'


def generate_shstrtab_binary(has_bss):
    """Генерирует бинарную таблицу имён секций (как в kvs_8.py)"""
    # Формат: \0.text\0.data\0.comment\0.shstrtab\0
    # (и .bss если есть)
    if has_bss:
        # .text, .data, .bss, .comment, .shstrtab
        names = ['', '.text', '.data', '.bss', '.comment', '.shstrtab']
    else:
        # .text, .data, .comment, .shstrtab
        names = ['', '.text', '.data', '.comment', '.shstrtab']
    
    result = b''
    for name in names:
        result += name.encode('ascii') + b'\x00'
    
    return result


def create_null_section_entry(shdr_offset):
    """Создаёт нулевую секцию (индекс 0) — все поля нулевые (sh_addralign=1 как в эталоне)"""
    entries = []
    # 64 байта нулей для нулевой секции
    for j in range(64):
        if 48 <= j <= 55:
            byte_val = 0x01 if j == 48 else 0x00
        else:
            byte_val = 0x00
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


def create_section_table_entries(sections, has_bss, shdr_offset, shstrtab_offset, comment_offset, comment_size, shstrtab_data):
    """Создаёт записи таблицы секций для CSV (с нулевой секцией, .comment и .shstrtab)"""
    
    if DEBUG_PRINTS:
        print("\n[DEBUG] create_section_table_entries")
        print(f"  has_bss = {has_bss}")
        print(f"  shdr_offset = 0x{shdr_offset:x}")
        print(f"  shstrtab_offset = 0x{shstrtab_offset:x}")
        print(f"  comment_offset = 0x{comment_offset:x}")
        print(f"  comment_size = {comment_size}")
    
    entries = []
    
    # Сначала добавляем НУЛЕВУЮ СЕКЦИЮ (индекс 0)
    null_entries = create_null_section_entry(shdr_offset)
    entries.extend(null_entries)
    
    if DEBUG_PRINTS:
        print(f"  Нулевая секция: {len(null_entries)} байт по адресу 0x{shdr_offset:x}")
    
    # Смещение для следующей секции (после нулевой)
    next_offset = shdr_offset + 64
    
    if DEBUG_PRINTS:
        print(f"  next_offset = 0x{next_offset:x} (начало заголовков секций)")
    
    # Вычисляем индексы имён в .shstrtab в зависимости от наличия BSS
    if has_bss:
        idx_text = 1
        idx_data = 7
        idx_bss = 13
        idx_comment = 17
        idx_shstrtab = 22
    else:
        idx_text = 1
        idx_data = 7
        idx_comment = 13
        idx_shstrtab = 22
    
    if DEBUG_PRINTS:
        print(f"  Индексы в .shstrtab:")
        print(f"    idx_text = {idx_text}")
        print(f"    idx_data = {idx_data}")
        if has_bss:
            print(f"    idx_bss = {idx_bss}")
        print(f"    idx_comment = {idx_comment}")
        print(f"    idx_shstrtab = {idx_shstrtab}")
    
    # 1. Заголовок для .text (индекс 1)
    header_text = struct.pack('<IIQQQQIIQQ',
        idx_text, 1, 6,  # SHT_PROGBITS, SHF_ALLOC|SHF_EXECINSTR
        sections['.text']['virt_start'],
        sections['.text']['start'],
        sections['.text']['size'],
        0, 0, 16, 0)
    
    if DEBUG_PRINTS:
        print(f"\n  Заголовок .text (64 байта):")
        print(f"    sh_name = {idx_text} (должно быть 1)")
        print(f"    sh_type = 1")
        print(f"    sh_flags = 6")
        print(f"    sh_addr = 0x{sections['.text']['virt_start']:x}")
        print(f"    sh_offset = 0x{sections['.text']['start']:x}")
        print(f"    sh_size = {sections['.text']['size']}")
        print(f"    Первые 4 байта (sh_name): {header_text[0:4].hex()}")
    
    # 2. Заголовок для .data (индекс 2)
    header_data = struct.pack('<IIQQQQIIQQ',
        idx_data, 1, 3,  # SHT_PROGBITS, SHF_ALLOC|SHF_WRITE
        sections['.data']['virt_start'],
        sections['.data']['start'],
        sections['.data']['size'],
        0, 0, 8, 0)
    
    if DEBUG_PRINTS:
        print(f"\n  Заголовок .data (64 байта):")
        print(f"    sh_name = {idx_data} (должно быть 7)")
        print(f"    Первые 4 байта (sh_name): {header_data[0:4].hex()}")
    
    headers = [header_text, header_data]
    header_names = ['.text', '.data']
    
    # 3. Заголовок для .bss (если есть)
    if has_bss:
        total_bss = sum(b['size'] for b in sections.get('bss', [])) if isinstance(sections.get('bss'), list) else 0
        header_bss = struct.pack('<IIQQQQIIQQ',
            idx_bss, 8, 3,  # SHT_NOBITS, SHF_ALLOC|SHF_WRITE
            0, 0, total_bss,
            0, 0, 16, 0)
        headers.append(header_bss)
        header_names.append('.bss')
        if DEBUG_PRINTS:
            print(f"\n  Заголовок .bss (64 байта):")
            print(f"    sh_name = {idx_bss} (должно быть 13)")
            print(f"    Первые 4 байта (sh_name): {header_bss[0:4].hex()}")
    
    # 4. Заголовок для .comment
    header_comment = struct.pack('<IIQQQQIIQQ',
        idx_comment, 1, 0,  # SHT_PROGBITS, no flags
        0, comment_offset, comment_size,
        0, 0, 1, 0)
    headers.append(header_comment)
    header_names.append('.comment')
    
    if DEBUG_PRINTS:
        print(f"\n  Заголовок .comment (64 байта):")
        print(f"    sh_name = {idx_comment} (должно быть 13 или 17)")
        print(f"    Первые 4 байта (sh_name): {header_comment[0:4].hex()}")
    
    # 5. Заголовок для .shstrtab (последний)
    shstrtab_size = len(shstrtab_data)
    header_shstrtab = struct.pack('<IIQQQQIIQQ',
        idx_shstrtab, 3, 0,  # SHT_STRTAB, no flags
        0, shstrtab_offset, shstrtab_size,
        0, 0, 1, 0)
    headers.append(header_shstrtab)
    header_names.append('.shstrtab')
    
    if DEBUG_PRINTS:
        print(f"\n  Заголовок .shstrtab (64 байта):")
        print(f"    sh_name = {idx_shstrtab} (должно быть 22)")
        print(f"    Первые 4 байта (sh_name): {header_shstrtab[0:4].hex()}")
    
    # Записываем остальные заголовки секций
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
    
    return entries, len(headers) + 1  # +1 для нулевой секции


def regenerate_program_headers_in_csv(csv_file, sections, has_bss, text_offset, data_offset):
    """Обновляет программные заголовки по адресу, вставляет новые при необходимости"""
    
    # Читаем CSV
    with open(csv_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f, delimiter=';')
        fieldnames = reader.fieldnames
        rows = list(reader)
    
    # Функция для получения числового адреса
    def get_addr_num(row):
        addr_str = row.get('адрес', '')
        if addr_str and addr_str != 'BSS' and addr_str.startswith('0x'):
            try:
                return int(addr_str, 16)
            except:
                return None
        return None
    
    # Создаём словарь существующих строк по адресу
    addr_to_row = {}
    rows_without_addr = []  # Строки без адреса (BSS и т.д.)
    
    for row in rows:
        addr = get_addr_num(row)
        if addr is not None:
            addr_to_row[addr] = row
        else:
            rows_without_addr.append(row)
    
    # Вычисляем размеры
    text_size = sections['.text']['size']
    data_size = sections['.data']['size']
    bss_size = 0
    vaddr_text = sections['.text']['virt_start']
    vaddr_data = sections['.data']['virt_start']
    text_memsz = align_up(text_size, PAGE_SIZE)
    data_memsz = align_up(data_size + bss_size, PAGE_SIZE)
    
    # Генерируем новые записи
    new_entries = []  # (addr, row)
    
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
    
    # Генерируем байтовые записи
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
    
    # ОБНОВЛЯЕМ существующие строки по адресу
    for addr, new_row in new_entries:
        addr_to_row[addr] = new_row  # Заменяем или добавляем
    
    # Сортируем все адреса
    sorted_addrs = sorted(addr_to_row.keys())
    
    # Собираем итоговые строки
    final_rows = []
    for addr in sorted_addrs:
        final_rows.append(addr_to_row[addr])
    
    # Добавляем строки без адресов в конец
    final_rows.extend(rows_without_addr)
    
    # Записываем обратно
    with open(csv_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, delimiter=';', restval='')
        writer.writeheader()
        writer.writerows(final_rows)
    
    print(f"✅ Программные заголовки обновлены в {csv_file}")
    print(f"   Обновлено/добавлено записей: {len(new_entries)}")
    print(f"   Всего записей с адресами: {len(sorted_addrs)}")

def update_elf_header_in_csv(csv_file, e_shoff, e_shnum, e_shentsize):
    """Обновляет ELF-заголовок в CSV файле"""
    
    rows = []
    with open(csv_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f, delimiter=';')
        fieldnames = reader.fieldnames
        for row in reader:
            rows.append(row)
    
    # e_shoff (8 байт по смещению 0x28-0x2f)
    shoff_bytes = struct.pack('<Q', e_shoff)
    for i in range(8):
        addr = f"0x{0x28 + i:08x}"
        for row in rows:
            if row['адрес'] == addr:
                row['рассчитанный_байт'] = f"0x{shoff_bytes[i]:02x}"
                row['байт'] = f"0x{shoff_bytes[i]:02x}"
                row['исходная_команда'] = f"e_shoff = 0x{e_shoff:x}"
    
    # e_shnum (2 байта по смещению 0x3c-0x3d)
    shnum_bytes = struct.pack('<H', e_shnum)
    for i in range(2):
        addr = f"0x{0x3c + i:08x}"
        for row in rows:
            if row['адрес'] == addr:
                row['рассчитанный_байт'] = f"0x{shnum_bytes[i]:02x}"
                row['байт'] = f"0x{shnum_bytes[i]:02x}"
                row['исходная_команда'] = f"e_shnum = {e_shnum}"
    
    # e_shentsize (2 байта по смещению 0x3a-0x3b)
    shentsize_bytes = struct.pack('<H', e_shentsize)
    for i in range(2):
        addr = f"0x{0x3a + i:08x}"
        for row in rows:
            if row['адрес'] == addr:
                row['рассчитанный_байт'] = f"0x{shentsize_bytes[i]:02x}"
                row['байт'] = f"0x{shentsize_bytes[i]:02x}"
                row['исходная_команда'] = f"e_shentsize = {e_shentsize}"
    
    # e_shstrndx (2 байта по смещению 0x3e-0x3f)
    e_shstrndx = e_shnum - 1
    shstrndx_bytes = struct.pack('<H', e_shstrndx)
    for i in range(2):
        addr = f"0x{0x3e + i:08x}"
        for row in rows:
            if row['адрес'] == addr:
                row['рассчитанный_байт'] = f"0x{shstrndx_bytes[i]:02x}"
                row['байт'] = f"0x{shstrndx_bytes[i]:02x}"
                row['исходная_команда'] = f"e_shstrndx = {e_shstrndx}"
    
    # e_phnum (2 байта по смещению 0x38-0x39)
    phnum_bytes = struct.pack('<H', 3)
    for i in range(2):
        addr = f"0x{0x38 + i:08x}"
        for row in rows:
            if row['адрес'] == addr:
                row['рассчитанный_байт'] = f"0x{phnum_bytes[i]:02x}"
                row['байт'] = f"0x{phnum_bytes[i]:02x}"
                row['исходная_команда'] = f"e_phnum = 3"
    
    # e_phoff (8 байт по смещению 0x20-0x27)
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
    
    # Проверка на дубликаты адресов
    existing_addrs = set()
    for row in rows:
        addr = row['адрес']
        if addr and addr != 'BSS':
            existing_addrs.add(addr)
    
    # Добавляем записи таблицы секций
    new_count = 0
    for entry in section_entries:
        if entry['адрес'] not in existing_addrs:
            rows.append(entry)
            existing_addrs.add(entry['адрес'])
            new_count += 1
    
    # Добавляем записи .comment
    for entry in comment_entries:
        if entry['адрес'] not in existing_addrs:
            rows.append(entry)
            existing_addrs.add(entry['адрес'])
            new_count += 1
    
    # Добавляем записи .shstrtab
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
    """Создаёт записи для данных .shstrtab (включая начальный нулевой байт)"""
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


def print_section_info(sections, has_bss, max_addr):
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
        print(f"   Присутствует (индексы в .shstrtab сдвинуты)")
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
    
    sections, bss_blocks, max_addr = analyze_csv(csv_file)
    has_bss = len(bss_blocks) > 0
    print_section_info(sections, has_bss, max_addr)
    
    # Вычисляем смещения (как в kvs_8.py)
    text_offset = sections['.text']['start']
    data_offset = sections['.data']['start']
    text_size = sections['.text']['size']
    data_size = sections['.data']['size']
    
    # Размеры данных
    comment_data = generate_comment_data()
    comment_size = len(comment_data)
    
    # Порядок размещения (как в kvs_8.py):
    # 1. .text (0x1000)
    # 2. .data (0x2000)
    # 3. .comment (сразу после .data)
    comment_offset = data_offset + data_size
    print(f"   comment_offset = 0x{comment_offset:x}")
    
    # 4. .shstrtab (выравнивание на 8 байт после .comment)
    shstrtab_data = generate_shstrtab_binary(has_bss)
    shstrtab_size = len(shstrtab_data)
    shstrtab_offset = align_up(comment_offset + comment_size, 8)
    print(f"   shstrtab_offset = 0x{shstrtab_offset:x}")
    print(f"   shstrtab_size = {shstrtab_size}")
    
    # 5. Таблица секций (выравнивание на 16 байт после .shstrtab)
    # Количество секций: NULL + .text + .data + .comment + .shstrtab (+ .bss если есть)
    num_sections = 5  # NULL + .text + .data + .comment + .shstrtab
    if has_bss:
        num_sections += 1  # + .bss
    
    # Таблица секций размещается после .shstrtab
    shdr_offset = align_up(shstrtab_offset + shstrtab_size, 16)
    print(f"   shdr_offset = 0x{shdr_offset:x}")
    
    print(f"\n📍 Размещение секций (как в kvs_8.py):")
    print(f"   .data: 0x{data_offset:08x}")
    print(f"   .comment: 0x{comment_offset:08x} (размер {comment_size} байт)")
    print(f"   .shstrtab: 0x{shstrtab_offset:08x} (размер {shstrtab_size} байт)")
    print(f"   Таблица секций: 0x{shdr_offset:08x}")
    print(f"   Количество секций: {num_sections}")
    print(f"   Наличие BSS: {has_bss}")
    
    # ПЕРЕСОЗДАЁМ ПРОГРАММНЫЕ ЗАГОЛОВКИ
    regenerate_program_headers_in_csv(csv_file, sections, has_bss, text_offset, data_offset)
    
    # Генерируем записи таблицы секций
    entries, num_headers = create_section_table_entries(
        sections, has_bss, shdr_offset, shstrtab_offset, comment_offset, comment_size, shstrtab_data
    )
    
    # Генерируем данные для .comment
    comment_entries = add_comment_data(comment_offset)
    
    # Генерируем данные для .shstrtab
    shstrtab_entries = add_shstrtab_data(shstrtab_offset, shstrtab_data)
    
    e_shoff = shdr_offset
    e_shnum = num_headers
    e_shentsize = 64
    
    print(f"\n📝 Обновление ELF-заголовка:")
    print(f"   e_shoff = 0x{e_shoff:08x}")
    print(f"   e_shnum = {e_shnum}")
    print(f"   e_shentsize = {e_shentsize}")
    
    # Обновляем ELF-заголовок в CSV
    update_elf_header_in_csv(csv_file, e_shoff, e_shnum, e_shentsize)
    
    # Добавляем таблицу секций, .comment и .shstrtab в CSV
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
        print(f"   BSS присутствует → индекс .shstrtab = 21")
    else:
        print(f"   BSS отсутствует → индекс .shstrtab = 21")


if __name__ == "__main__":
    main()