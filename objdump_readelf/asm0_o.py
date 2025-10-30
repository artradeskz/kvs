#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Скрипт генерирует 64-битный исполняемый ELF-файл для Linux (x86-64),
# содержащий 12 инструкций NOP (0x90) в секции .text и один байт (0x0A)
# в секции .data. Файл полностью корректен и распознаётся утилитами
# objdump, readelf и другими стандартными инструментами.

import struct

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

    # Таблица имён секций (.shstrtab) размещается сразу после .data
    shstrtab_offset = data_offset + len(data_content)  # 0x2000 + 1 = 0x2001

    # Заголовки секций (Section Headers) размещаются сразу после .shstrtab
    shdr_offset = shstrtab_offset + len(shstrtab_content)

    # === РАЗМЕРЫ КОМПОНЕНТОВ ===
    text_size = len(text_code)        # 12 байт
    data_size = len(data_content)     # 1 байт
    shstrtab_size = len(shstrtab_content)  # длина строки имён

    # Размер одного заголовка секции — 64 байта для 64-битного ELF
    # Всего 4 секции: NULL, .text, .data, .shstrtab
    shdr_size = 4 * 64

    # Общий размер файла: от начала до конца последнего заголовка секции
    file_size = shdr_offset + shdr_size

    # Создаём байтовый массив нужного размера, заполненный нулями
    elf_data = bytearray(file_size)

    # === 1. ELF-ЗАГОЛОВОК (64 байта) ===
    # e_ident — магическое число и базовые параметры формата
    e_ident = (
        b'\x7fELF'      # Магическое число ELF
        b'\x02'         # 64-битный файл
        b'\x01'         # Little-endian (младший байт первым)
        b'\x01'         # Версия ELF (1)
        b'\x00' * 9     # Остальные поля e_ident — нули (OSABI=System V и т.д.)
    )

    # Упаковываем ELF-заголовок в бинарный формат
    # Формат: < — little-endian; 16s — 16 байт; H — uint16; I — uint32; Q — uint64
    elf_header = struct.pack(
        '<16sHHIQQQIHHHHHH',
        e_ident,        # e_ident[16]
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
    # Функция для создания одного Program Header (PT_LOAD)
    def make_phdr(p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align):
        """
        Создаёт бинарное представление заголовка сегмента.
        Поля:
          p_type   — тип сегмента (1 = PT_LOAD)
          p_flags  — права доступа (PF_R=4, PF_W=2, PF_X=1)
          p_offset — смещение сегмента в файле
          p_vaddr  — виртуальный адрес загрузки в памяти
          p_paddr  — физический адрес (в Linux не используется, = vaddr)
          p_filesz — размер данных в файле
          p_memsz  — размер в памяти (может быть больше для .bss)
          p_align  — выравнивание (обычно PAGE_SIZE)
        """
        return struct.pack('<IIQQQQQQ',
            p_type, p_flags,
            p_offset,
            p_vaddr,
            p_paddr,
            p_filesz,
            p_memsz,
            p_align
        )

    # Сегмент 0: заголовки ELF и Program Headers (только чтение)
    ph0 = make_phdr(
        p_type=1,           # PT_LOAD
        p_offset=0x0000,    # смещение в файле
        p_vaddr=0x400000,   # адрес в памяти
        p_paddr=0x400000,
        p_filesz=0xe8,      # 232 байта (ELF + 3×PHDR)
        p_memsz=0xe8,
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

    # Записываем таблицу имён секций (.shstrtab)
    elf_data[shstrtab_offset : shstrtab_offset + shstrtab_size] = shstrtab_content

    # === 4. SECTION HEADERS (заголовки секций) ===
    # Функция для создания одного Section Header
    def make_shdr(name_idx, sh_type, flags, addr, offset, size, link=0, info=0, addralign=1, entsize=0):
        """
        Создаёт бинарное представление заголовка секции.
        Поля:
          name_idx   — индекс имени в .shstrtab
          sh_type    — тип секции (1 = SHT_PROGBITS, 3 = SHT_STRTAB)
          flags      — флаги (SHF_WRITE=1, SHF_ALLOC=2, SHF_EXECINSTR=4)
          addr       — виртуальный адрес в памяти (0, если не загружается)
          offset     — смещение в файле
          size       — размер секции
          link, info — дополнительные ссылки (обычно 0)
          addralign  — выравнивание (1 = без выравнивания)
          entsize    — размер записи (для таблиц, иначе 0)
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
        size=text_size
    )

    # Секция 2: .data — инициализированные данные
    sh2 = make_shdr(
        name_idx=7,         # ".data" начинается с байта 7
        sh_type=1,
        flags=3,            # SHF_ALLOC | SHF_WRITE = 2 + 1
        addr=0x402000,
        offset=data_offset,
        size=data_size
    )

    # Секция 3: .shstrtab — таблица имён секций
    sh3 = make_shdr(
        name_idx=13,        # ".shstrtab" начинается с байта 13
        sh_type=3,          # SHT_STRTAB — таблица строк
        flags=0,
        addr=0,
        offset=shstrtab_offset,
        size=shstrtab_size
    )

    # Собираем все заголовки секций и записываем в файл
    section_headers = sh0 + sh1 + sh2 + sh3
    elf_data[shdr_offset : shdr_offset + len(section_headers)] = section_headers

    # Возвращаем готовый ELF-файл как неизменяемые байты
    return bytes(elf_data)

if __name__ == '__main__':
    # Генерируем ELF и записываем в файл
    with open('nop12_fixed.elf', 'wb') as f:
        f.write(pack_elf())
    
    # Выводим информационные сообщения
    print("Создан файл nop12_fixed.elf")
    print("  Проверьте его содержимое командами:")
    print("    objdump -D nop12_fixed.elf")
    print("    readelf -l nop12_fixed.elf")
    print("    readelf -S nop12_fixed.elf") 
    print("    eu-readelf -a nop12_fixed.elf")