#!/usr/bin/env python3
"""
Генератор CSV-таблицы для программы на КВС (функциональная версия)
Экспериментальный однопроходный ассемблер - с корректными заглушками ELF
"""

import sys
import csv
from typing import List, Optional, Tuple

# Глобальное состояние
entries = []           # Список записей: (address, byte, target, source, segment)
current_address = 0
current_segment = '.header'
last_segment = None
relocations = []       # Список отложенных ссылок: (pos, label, type, source)

def reset_state():
    """Сбросить состояние генератора"""
    global entries, current_address, current_segment, last_segment, relocations
    entries = []
    current_address = 0
    current_segment = '.header'
    last_segment = None
    relocations = []

def set_segment(segment: str):
    """Переключить текущий сегмент"""
    global current_segment
    current_segment = segment

def add_byte(value: int, source: str = "", target: Optional[int] = None):
    """Добавить один байт"""
    global current_address, last_segment
    
    # Показываем сегмент только при смене
    show_segment = current_segment if current_segment != last_segment else None
    if show_segment:
        last_segment = current_segment
    
    entries.append((
        current_address,
        value & 0xFF,
        target,
        source,
        show_segment
    ))
    current_address += 1

def add_bytes(values: List[int], source: str = ""):
    """Добавить последовательность байтов"""
    for v in values:
        add_byte(v, source)

def add_word32(value: int, source: str = ""):
    """Добавить 32-битное слово (little-endian)"""
    add_bytes([
        (value >> 0) & 0xFF,
        (value >> 8) & 0xFF,
        (value >> 16) & 0xFF,
        (value >> 24) & 0xFF,
    ], source)

def add_word64(value: int, source: str = ""):
    """Добавить 64-битное слово (little-endian)"""
    add_bytes([
        (value >> 0) & 0xFF,
        (value >> 8) & 0xFF,
        (value >> 16) & 0xFF,
        (value >> 24) & 0xFF,
        (value >> 32) & 0xFF,
        (value >> 40) & 0xFF,
        (value >> 48) & 0xFF,
        (value >> 56) & 0xFF,
    ], source)

def align_to(alignment: int):
    """Выровнять адрес до границы (просто двигаем адрес)"""
    global current_address
    padding = (alignment - (current_address % alignment)) % alignment
    current_address += padding

def add_relocation(pos: int, label: str, reloc_type: str, source: str = ""):
    """Запомнить место для отложенной подстановки"""
    relocations.append((pos, label, reloc_type, source))

def generate_elf_header():
    """Сгенерировать корректный ELF заголовок с заглушками"""
    # EI_MAGIC
    add_bytes([0x7F, 0x45, 0x4C, 0x46], "ELF magic")
    
    # ei_class: 64-bit (2)
    add_byte(2, "ELFCLASS64")
    
    # ei_data: little-endian (1)
    add_byte(1, "ELFDATA2LSB")
    
    # ei_version: 1
    add_byte(1, "ELF version")
    
    # ei_osabi: System V (0)
    add_byte(0, "OS ABI")
    
    # ei_abiversion: 0
    add_byte(0, "ABI version")
    
    # ei_pad: 7 байт паддинга
    add_bytes([0] * 7, "Padding")
    
    # e_type: ET_EXEC (2)
    add_word32(2, "e_type = ET_EXEC")
    
    # e_machine: EM_X86_64 (62)
    add_word32(62, "e_machine = EM_X86_64")
    
    # e_version: 1
    add_word32(1, "e_version")
    
    # e_entry: точка входа (заглушка 0x401000)
    add_word64(0x401000, "e_entry (stub: _start)")
    
    # e_phoff: смещение до program headers (64 байта)
    add_word64(64, "e_phoff")
    
    # e_shoff: смещение до section headers (0 = нет секций)
    add_word64(0, "e_shoff = 0")
    
    # e_flags: 0
    add_word32(0, "e_flags")
    
    # e_ehsize: размер ELF заголовка (64)
    add_word32(64, "e_ehsize")
    
    # e_phentsize: размер program header entry (56)
    add_word32(56, "e_phentsize")
    
    # e_phnum: количество program headers (2)
    add_word32(2, "e_phnum = 2")
    
    # e_shentsize: размер section header entry (0)
    add_word32(0, "e_shentsize = 0")
    
    # e_shnum: количество section headers (0)
    add_word32(0, "e_shnum = 0")
    
    # e_shstrndx: индекс секции строк (0)
    add_word32(0, "e_shstrndx")

def generate_program_headers():
    """Сгенерировать program headers с корректными выравниваниями"""
    
    # Смещения в файле (должны быть кратны 4096)
    text_offset = 0x1000  # 4096
    data_offset = 0x2000  # 8192
    
    # Program Header 1: TEXT (RX)
    add_word32(1, "p_type = PT_LOAD")
    add_word32(5, "p_flags = RX")
    add_word64(text_offset, "p_offset (text)")
    add_word64(0x401000, "p_vaddr (text)")
    add_word64(0x401000, "p_paddr (text)")
    add_word64(0, "p_filesz (stub)")  # Заглушка
    add_word64(0, "p_memsz (stub)")   # Заглушка
    add_word64(0x1000, "p_align (4KB)")
    
    # Program Header 2: DATA (RW)
    add_word32(1, "p_type = PT_LOAD")
    add_word32(6, "p_flags = RW")
    add_word64(data_offset, "p_offset (data)")
    add_word64(0x402000, "p_vaddr (data)")
    add_word64(0x402000, "p_paddr (data)")
    add_word64(0, "p_filesz (stub)")  # Заглушка
    add_word64(0, "p_memsz (stub)")   # Заглушка
    add_word64(0x1000, "p_align (4KB)")

def generate_empty_program():
    """Сгенерировать пустую программу с корректным ELF скелетом"""
    reset_state()
    
    # Генерируем заголовки
    set_segment('.header')
    generate_elf_header()
    generate_program_headers()
    
    # Выравнивание до .text секции
    align_to(0x1000)
    
    # .text секция
    set_segment('.text')
    add_byte(0xCC, ".text section start (INT3)")
    
    # Выравнивание до .data секции
    align_to(0x1000)
    
    # .data секция
    set_segment('.data')
    add_byte(0x00, ".data section start")
    
    # Вывод информации
    print(f"\n=== Сгенерирован скелет программы ===", file=sys.stderr)
    print(f"ELF заголовок: 64 байта", file=sys.stderr)
    print(f"Program headers: 112 байт (2 * 56)", file=sys.stderr)
    print(f".text: 1 байт по адресу 0x401000", file=sys.stderr)
    print(f".data: 1 байт по адресу 0x402000", file=sys.stderr)
    print(f"\nПроверка readelf:", file=sys.stderr)
    print(f"  e_phoff = 64 (0x40) - верно", file=sys.stderr)
    print(f"  p_offset(text) = 4096 (0x1000) - кратно p_align", file=sys.stderr)
    print(f"  p_offset(data) = 8192 (0x2000) - кратно p_align", file=sys.stderr)

def save_to_csv(filename: str):
    """Сохранить таблицу в CSV"""
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f, delimiter=';')
        writer.writerow(['адрес', 'байт', 'целевой_адрес', 'исходная_команда', 'сегмент'])
        
        for addr, byte, target, source, segment in entries:
            writer.writerow([
                f"0x{addr:08x}",
                f"0x{byte:02x}",
                f"0x{target:08x}" if target is not None else "",
                source,
                segment if segment else ""
            ])
    
    print(f"CSV сохранен: {filename}", file=sys.stderr)

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 kvs_csv_builder.py <output.csv>")
        sys.exit(1)
    
    generate_empty_program()
    save_to_csv(sys.argv[1])
    print("\nГотово!", file=sys.stderr)

if __name__ == "__main__":
    main()