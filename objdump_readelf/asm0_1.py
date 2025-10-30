#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Скрипт генерирует КОРРЕКТНЫЙ 64-битный исполняемый ELF-файл для Linux (x86-64),
# содержащий 12 инструкций NOP (0x90) в секции .text и один байт (0x0A) в секции .data.
# Файл полностью соответствует ELF-спецификации.

import struct

def align_up(offset, alignment):
    """Выравнивание offset вверх до alignment"""
    return (offset + alignment - 1) & ~(alignment - 1)

def pack_elf():
    """
    Создаёт байтовое представление валидного ELF-исполняемого файла.
    Возвращает bytes — содержимое файла.
    """
    # Размер страницы памяти в Linux на x86-64 (4096 байт = 0x1000)
    PAGE_SIZE = 0x1000

    # Адрес точки входа программы — начало секции .text
    ENTRY = 0x401000

    # === СОДЕРЖИМОЕ СЕКЦИЙ ===
    # Машинный код: 12 инструкций NOP (код операции 0x90)
    text_code = b'\x90' * 12

    # Данные: один байт — символ новой строки (0x0A = '\n')
    data_content = b'\x0a'

    # Таблица строк имён секций (обязательна для Section Headers)
    # Формат: нуль-терминированные строки подряд.
    # Порядок: "", ".text", ".data", ".shstrtab"
    shstrtab_content = b'\x00.text\x00.data\x00.shstrtab\x00'

    # === СМЕЩЕНИЯ В ФАЙЛЕ (в байтах) ===
    # Program Headers (заголовки сегментов) начинаются сразу после ELF-заголовка
    phdr_start = 64  # размер ELF-заголовка

    # Секция .text начинается с границы страницы 0x1000 (4096)
    text_offset = 0x1000

    # Секция .data начинается со следующей страницы — 0x2000 (8192)
    data_offset = 0x2000

    # Таблица имён секций (.shstrtab) размещается сразу после .data с ВЫРАВНИВАНИЕМ
    shstrtab_offset = align_up(data_offset + len(data_content), 8)  # 0x2008 вместо 0x2001

    # Заголовки секций (Section Headers) размещаются сразу после .shstrtab с выравниванием
    shdr_offset = align_up(shstrtab_offset + len(shstrtab_content), 16)  # 0x2020

    # === РАЗМЕРЫ КОМПОНЕНТОВ ===
    text_size = len(text_code)        # 12 байт
    data_size = len(data_content)     # 1 байт
    shstrtab_size = len(shstrtab_content)  # 17 байт

    # Размер Program Headers: 3 заголовка × 56 байт
    phdr_size = 3 * 56  # 168 байт

    # Размер одного заголовка секции — 64 байта для 64-битного ELF
    # Всего 4 секции: NULL, .text, .data, .shstrtab
    shdr_size = 4 * 64  # 256 байт

    # Общий размер файла: от начала до конца последнего заголовка секции
    file_size = shdr_offset + shdr_size  # 0x2020 + 256 = 0x2120 (8480 байт)

    # Создаём байтовый массив нужного размера, заполненный нулями
    elf_data = bytearray(file_size)

    # === 1. ELF-ЗАГОЛОВОК (64 байта) ===
    # e_ident — магическое число и базовые параметры формата (ИСПРАВЛЕНО)
    # Структура e_ident: 16 байт
    e_ident = (
        b'\x7fELF'         # ELF Magic (4 байта)
        b'\x02'            # 64-bit (1 байт)
        b'\x01'            # Little-endian (1 байт)  
        b'\x01'            # ELF Version (1 байт)
        b'\x00'            # OS ABI: System V (1 байт)
        b'\x00'            # ABI Version (1 байт)
        b'\x00\x00\x00\x00\x00\x00\x00'  # Padding (7 байт) - ИТОГО 16 байт
    )
    
    assert len(e_ident) == 16, f"e_ident должен быть 16 байт, а не {len(e_ident)}"

    # Упаковываем ELF-заголовок в бинарный формат
    elf_header = struct.pack(
        '<16sHHIQQQIHHHHHH',
        e_ident,        # e_ident[16] - 16 байт
        2,              # e_type        = ET_EXEC (исполняемый файл)
        0x3e,           # e_machine     = EM_X86_64 (AMD x86-64)
        1,              # e_version     = 1
        ENTRY,          # e_entry       — адрес точки входа
        phdr_start,     # e_phoff       — смещение Program Headers в файле
        shdr_offset,    # e_shoff       — смещение Section Headers в файле
        0,              # e_flags       — флаги архитектуры (0 для x86-64)
        64,             # e_ehsize      — размер ELF-заголовка (64 байта)
        56,             # e_phentsize   — размер одного Program Header (56 байт)
        3,              # e_phnum       — количество Program Headers
        64,             # e_shentsize   — размер одного Section Header (64 байта)
        4,              # e_shnum       — количество Section Headers
        3               # e_shstrndx    — индекс секции с именами (.shstrtab)
    )
    # Записываем ELF-заголовок в начало файла
    elf_data[0:64] = elf_header

    # === 2. PROGRAM HEADERS (заголовки сегментов) ===
    def make_phdr(p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align):
        """
        Создаёт бинарное представление заголовка сегмента.
        """
        # Проверки корректности
        assert p_offset % p_align == 0, f"Segment offset {p_offset:#x} not aligned to {p_align:#x}"
        assert p_vaddr % p_align == 0, f"Virtual address {p_vaddr:#x} not aligned to {p_align:#x}"
        assert p_filesz <= p_memsz, f"File size {p_filesz:#x} > memory size {p_memsz:#x}"
        
        return struct.pack('<IIQQQQQQ',
            p_type, p_flags,
            p_offset,
            p_vaddr,
            p_paddr,
            p_filesz,
            p_memsz,
            p_align
        )

    # Сегмент 0: заголовки ELF и Program Headers (чтение и выполнение для корректности)
    ph0 = make_phdr(
        p_type=1,           # PT_LOAD
        p_offset=0x0000,    # смещение в файле
        p_vaddr=0x400000,   # адрес в памяти
        p_paddr=0x400000,
        p_filesz=phdr_start + phdr_size,  # 64 + 168 = 232 (0xe8) байт
        p_memsz=PAGE_SIZE,  # В памяти занимает целую страницу
        p_flags=4,          # PF_R — только чтение
        p_align=PAGE_SIZE
    )

    # Сегмент 1: исполняемый код (.text)
    ph1 = make_phdr(
        p_type=1,
        p_offset=text_offset,   # 0x1000
        p_vaddr=0x401000,       # адрес точки входа
        p_paddr=0x401000,
        p_filesz=text_size,     # 12 байт
        p_memsz=text_size,
        p_flags=5,              # PF_R | PF_X = 4 + 1
        p_align=PAGE_SIZE
    )

    # Сегмент 2: данные (.data)
    ph2 = make_phdr(
        p_type=1,
        p_offset=data_offset,   # 0x2000
        p_vaddr=0x402000,
        p_paddr=0x402000,
        p_filesz=data_size,     # 1 байт
        p_memsz=data_size,
        p_flags=6,              # PF_R | PF_W = 4 + 2
        p_align=PAGE_SIZE
    )

    # Записываем все Program Headers в файл по смещению 64
    program_headers = ph0 + ph1 + ph2
    elf_data[phdr_start : phdr_start + len(program_headers)] = program_headers

    # === 3. СОДЕРЖИМОЕ СЕКЦИЙ ===
    # Записываем машинный код (.text) по смещению 0x1000
    elf_data[text_offset : text_offset + text_size] = text_code

    # Записываем данные (.data) по смещению 0x2000
    elf_data[data_offset : data_offset + data_size] = data_content

    # Записываем таблицу имён секций (.shstrtab) по ВЫРОВНЕННОМУ смещению
    elf_data[shstrtab_offset : shstrtab_offset + shstrtab_size] = shstrtab_content

    # === 4. SECTION HEADERS (заголовки секций) ===
    def make_shdr(name_idx, sh_type, flags, addr, offset, size, link=0, info=0, addralign=1, entsize=0):
        """
        Создаёт бинарное представление заголовка секции.
        """
        return struct.pack('<IIQQQQIIQQ',
            name_idx, sh_type, flags, addr, offset, size, link, info, addralign, entsize
        )

    # Индексы имён в .shstrtab:
    # Строка: "\x00.text\x00.data\x00.shstrtab\x00"
    # Индексы: 0   1     7     13

    # Секция 0: NULL (обязательна, пустая)
    sh0 = make_shdr(0, 0, 0, 0, 0, 0)

    # Секция 1: .text — исполняемый код
    sh1 = make_shdr(
        name_idx=1,         # ".text" начинается с байта 1
        sh_type=1,          # SHT_PROGBITS — обычная секция с данными
        flags=6,            # SHF_ALLOC | SHF_EXECINSTR = 2 + 4
        addr=0x401000,      # адрес в памяти
        offset=text_offset, # смещение в файле
        size=text_size,
        addralign=16        # Выравнивание 16 байт для кода
    )

    # Секция 2: .data — инициализированные данные
    sh2 = make_shdr(
        name_idx=7,         # ".data" начинается с байта 7
        sh_type=1,
        flags=3,            # SHF_ALLOC | SHF_WRITE = 2 + 1
        addr=0x402000,
        offset=data_offset,
        size=data_size,
        addralign=4         # Выравнивание 4 байта для данных
    )

    # Секция 3: .shstrtab — таблица имён секций
    sh3 = make_shdr(
        name_idx=13,        # ".shstrtab" начинается с байта 13
        sh_type=3,          # SHT_STRTAB — таблица строк
        flags=0,
        addr=0,
        offset=shstrtab_offset,
        size=shstrtab_size,
        addralign=1         # Без выравнивания для строк
    )

    # Собираем все заголовки секций и записываем в файл
    section_headers = sh0 + sh1 + sh2 + sh3
    elf_data[shdr_offset : shdr_offset + len(section_headers)] = section_headers

    # Возвращаем готовый ELF-файл как неизменяемые байты
    return bytes(elf_data)

if __name__ == '__main__':
    # Генерируем ELF и записываем в файл
    with open('nop12_correct.elf', 'wb') as f:
        f.write(pack_elf())
    
    # Выводим информационные сообщения
    print("Создан ИСПРАВЛЕННЫЙ файл nop12_correct.elf")
    print("  eu-readelf -a nop12_correct.elf")
    print("  objdump -D nop12_correct.elf")
    print("  readelf -l nop12_correct.elf")
    print("  file nop12_correct.elf")