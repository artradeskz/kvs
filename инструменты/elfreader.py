#!/usr/bin/env python3
"""
===============================================================================
ELF Reader — аналог readelf для ELF64 (AMD64/x86-64)
===============================================================================

НАЗНАЧЕНИЕ
----------
Модуль читает и отображает заголовки исполняемых ELF-файлов в стиле утилиты
readelf из пакета GNU Binutils. Вывод на русском языке, формат максимально
приближен к оригинальному readelf -h -l -S.

Поддерживается только архитектура AMD64 (x86-64), little-endian, 64-битный
формат ELF.

ИСПОЛЬЗОВАНИЕ
-------------
    python3 elfreader.py <путь_к_elf_файлу>

Пример:
    python3 elfreader.py /bin/ls
    python3 elfreader.py моя_программа.elf

ФУНКЦИОНАЛЬНОСТЬ
-----------------
Выводит три блока информации:

1. Заголовок ELF (readelf -h):
   - Magic-число и класс (ELF64)
   - Порядок байт (little-endian)
   - Тип файла (EXEC, DYN, REL, CORE)
   - Целевая машина (X86-64)
   - Адрес точки входа
   - Расположение и количество программных/секционных заголовков
   - Индекс строковой таблицы секций

2. Заголовки разделов (readelf -S):
   - Таблица всех секций с адресами, смещениями, размерами
   - Флаги секций (W=запись, A=выделение памяти, X=исполнение, I=инфо)
   - Поля ссылок, информации и выравнивания
   - Легенда обозначений флагов

3. Заголовки программы/сегментов (readelf -l):
   - Таблица сегментов с виртуальными/физическими адресами
   - Файловый и памяти'ный размеры
   - Флаги доступа (R=чтение, W=запись, E=исполнение)
   - Соответствие сегментов секциям

ВЫВОДИМЫЕ ДАННЫЕ
-----------------
Все числовые значения выводятся в шестнадцатеричном виде (адреса, смещения,
размеры) или десятичном (счётчики, индексы). Флаги секций и сегментов
отображаются в сокращённой буквенной нотации.

ОГРАНИЧЕНИЯ
-----------
- Только ELF64 little-endian (архитектура x86-64)
- Не поддерживаются 32-битные ELF-файлы
- Не анализируются таблицы символов (.symtab, .dynsym)
- Не обрабатываются релокации (.rel, .rela)
- Не читаются отладочные секции (.debug_*)
- Не разбираются динамические секции (.dynamic)
- Не интерпретируются NOTE-секции
- Не выводится информация о версиях символов
- Не читается интерпретатор из секции .interp

ТРЕБОВАНИЯ
----------
- Python 3.6 или выше
- Только стандартная библиотека (struct, sys)
- Внешние зависимости отсутствуют

АРХИТЕКТУРА МОДУЛЯ
-------------------
Весь код организован в виде набора чистых функций без классов:

Чтение структур:
    read_elf_header()         - парсинг основного ELF-заголовка (64 байта)
    read_section_headers()    - парсинг заголовков секций (по 64 байта каждый)
    read_program_headers()    - парсинг программных заголовков (по 56 байт каждый)
    get_section_name()        - извлечение имени секции из строковой таблицы

Форматирование вывода:
    format_elf_header()       - форматирование ELF-заголовка в строку
    format_sections()         - форматирование таблицы секций
    format_program_headers()  - форматирование таблицы сегментов
    format_segment_section_map() - форматирование связей сегменты->секции

Вспомогательные:
    get_flags_description()   - преобразование битовых флагов секции в строку

ФОРМАТ ELF64 (краткая справка)
-------------------------------
ELF-заголовок (Elf64_Ehdr):     64 байта
  - e_ident[16]: magic (4 байта), класс (1), порядок байт (1), версия (1),
                 OS/ABI (1), ABI version (1), padding (7)
  - e_type (2 байта): тип файла
  - e_machine (2 байта): архитектура (0x3E = x86-64)
  - e_version (4 байта): версия формата
  - e_entry (8 байт): адрес точки входа
  - e_phoff (8 байт): смещение таблицы программных заголовков
  - e_shoff (8 байт): смещение таблицы заголовков секций
  - e_flags (4 байта): флаги процессора
  - e_ehsize (2 байта): размер этого заголовка
  - e_phentsize (2 байта): размер одного программного заголовка
  - e_phnum (2 байта): количество программных заголовков
  - e_shentsize (2 байта): размер одного заголовка секции
  - e_shnum (2 байта): количество заголовков секций
  - e_shstrndx (2 байта): индекс секции со строковой таблицей имён секций

Заголовок секции (Elf64_Shdr):  64 байта
  - sh_name (4 байта): смещение имени в .shstrtab
  - sh_type (4 байта): тип секции
  - sh_flags (8 байт): флаги (W=1, A=2, X=4, I=0x8)
  - sh_addr (8 байт): виртуальный адрес в памяти
  - sh_offset (8 байт): смещение данных в файле
  - sh_size (8 байт): размер секции в байтах
  - sh_link (4 байта): ссылка на другую секцию
  - sh_info (4 байта): дополнительная информация
  - sh_addralign (8 байт): выравнивание адреса
  - sh_entsize (8 байт): размер элемента (для таблиц)

Программный заголовок (Elf64_Phdr): 56 байт
  - p_type (4 байта): тип сегмента (LOAD, DYNAMIC, INTERP, ...)
  - p_flags (4 байта): флаги доступа (R=4, W=2, E=1)
  - p_offset (8 байт): смещение данных в файле
  - p_vaddr (8 байт): виртуальный адрес загрузки
  - p_paddr (8 байт): физический адрес
  - p_filesz (8 байт): размер в файле
  - p_memsz (8 байт): размер в памяти
  - p_align (8 байт): выравнивание

ПРИМЕР ВЫВОДА
-------------
    $ python3 elfreader.py программа.elf

    Заголовок ELF:
      Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
      Класс:                             ELF64
      Данные:                            дополнение до 2, от младшего к старшему
      Version:                           1 (current)
      OS/ABI:                            UNIX - System V
      Версия ABI:                        0
      Тип:                               EXEC (Исполняемый файл)
      Машина:                            Advanced Micro Devices X86-64
      ...

ИНТЕГРАЦИЯ
----------
Модуль можно использовать как самостоятельную утилиту:

    python3 elfreader.py файл.elf

Или импортировать функции для программного анализа ELF-файлов:

    from elfreader import read_elf_header, read_section_headers
    
    with open('программа.elf', 'rb') as f:
        hdr = read_elf_header(f)
        print(f"Точка входа: 0x{hdr['e_entry']:x}")

СРАВНЕНИЕ С readelf
-------------------
Вывод elfreader.py максимально приближен к выводу readelf из GNU Binutils.
Основные отличия:
- Все заголовки на русском языке (Заголовок ELF, Заголовки разделов, ...)
- Незначительные различия в форматировании пробелов
- Отсутствует часть расширенной информации (символы, релокации, dynamic)
- Не отображается интерпретатор из секции .interp

Для полного анализа ELF-файлов рекомендуется использовать оригинальный
readelf или библиотеку pyelftools для программного доступа.

АВТОР И ЛИЦЕНЗИЯ
-----------------
Создано в образовательных целях для изучения формата ELF.
Свободное использование, модификация и распространение.
"""

import struct
import sys

# ---------- константы ELF64 ----------
ELFMAG = b'\x7fELF'
ELFCLASS64 = 2
ELFDATA2LSB = 1
EM_X86_64 = 0x3E

# Типы ELF (e_type)
ET_NONE = 0
ET_REL  = 1
ET_EXEC = 2
ET_DYN  = 3
ET_CORE = 4

ETYPE_NAMES = {
    ET_NONE: 'NONE (Нет типа файла)',
    ET_REL:  'REL (Перемещаемый файл)',
    ET_EXEC: 'EXEC (Исполняемый файл)',
    ET_DYN:  'DYN (Совместно используемый объектный файл)',
    ET_CORE: 'CORE (Файл ядра)'
}

# Типы секций (sh_type)
SHT_NULL            = 0
SHT_PROGBITS        = 1
SHT_SYMTAB          = 2
SHT_STRTAB          = 3
SHT_RELA            = 4
SHT_HASH            = 5
SHT_DYNAMIC         = 6
SHT_NOTE            = 7
SHT_NOBITS          = 8
SHT_REL             = 9
SHT_SHLIB           = 10
SHT_DYNSYM          = 11
SHT_INIT_ARRAY      = 14
SHT_FINI_ARRAY      = 15
SHT_PREINIT_ARRAY   = 16
SHT_GROUP           = 17
SHT_SYMTAB_SHNDX    = 18
SHT_NUM             = 19
SHT_GNU_HASH        = 0x6ffffff6
SHT_VERSYM          = 0x6fffffff
SHT_VERNEED         = 0x6ffffffe
SHT_VERDEF          = 0x6ffffffd

SHT_NAMES = {
    SHT_NULL:           'NULL',
    SHT_PROGBITS:       'PROGBITS',
    SHT_SYMTAB:         'SYMTAB',
    SHT_STRTAB:         'STRTAB',
    SHT_RELA:           'RELA',
    SHT_HASH:           'HASH',
    SHT_DYNAMIC:        'DYNAMIC',
    SHT_NOTE:           'NOTE',
    SHT_NOBITS:         'NOBITS',
    SHT_REL:            'REL',
    SHT_SHLIB:          'SHLIB',
    SHT_DYNSYM:         'DYNSYM',
    SHT_INIT_ARRAY:     'INIT_ARRAY',
    SHT_FINI_ARRAY:     'FINI_ARRAY',
    SHT_PREINIT_ARRAY:  'PREINIT_ARRAY',
    SHT_GROUP:          'GROUP',
    SHT_SYMTAB_SHNDX:   'SYMTAB_SHNDX',
    SHT_NUM:            'NUM',
    SHT_GNU_HASH:       'GNU_HASH',
    SHT_VERSYM:         'VERSYM',
    SHT_VERNEED:        'VERNEED',
    SHT_VERDEF:         'VERDEF'
}

# Типы программных заголовков (p_type)
PT_NULL    = 0
PT_LOAD    = 1
PT_DYNAMIC = 2
PT_INTERP  = 3
PT_NOTE    = 4
PT_SHLIB   = 5
PT_PHDR    = 6
PT_TLS     = 7
PT_GNU_EH_FRAME = 0x6474e550
PT_GNU_STACK    = 0x6474e551
PT_GNU_RELRO    = 0x6474e552
PT_GNU_PROPERTY = 0x6474e553

PT_NAMES = {
    PT_NULL:     'NULL',
    PT_LOAD:     'LOAD',
    PT_DYNAMIC:  'DYNAMIC',
    PT_INTERP:   'INTERP',
    PT_NOTE:     'NOTE',
    PT_SHLIB:    'SHLIB',
    PT_PHDR:     'PHDR',
    PT_TLS:      'TLS',
    PT_GNU_EH_FRAME: 'GNU_EH_FRAME',
    PT_GNU_STACK:    'GNU_STACK',
    PT_GNU_RELRO:    'GNU_RELRO',
    PT_GNU_PROPERTY: 'GNU_PROPERTY'
}

# OS/ABI идентификаторы
OSABI_NAMES = {
    0:  'UNIX - System V',
    1:  'HP-UX',
    2:  'NetBSD',
    3:  'GNU/Linux',
    6:  'Solaris',
    9:  'FreeBSD',
    12: 'OpenBSD'
}


# ---------- функции чтения структур ----------
def read_elf_header(f):
    """Читает и возвращает словарь с полями ELF-заголовка (64-бит)."""
    data = f.read(64)
    if len(data) < 64:
        raise ValueError("Слишком маленький файл для ELF64 заголовка")

    fmt = '16s H H I Q Q Q I H H H H H H'
    (e_ident, e_type, e_machine, e_version,
     e_entry, e_phoff, e_shoff, e_flags,
     e_ehsize, e_phentsize, e_phnum,
     e_shentsize, e_shnum, e_shstrndx) = struct.unpack(fmt, data)

    if e_ident[:4] != ELFMAG:
        raise ValueError("Не ELF файл")
    if e_ident[4] != ELFCLASS64:
        raise ValueError("Не 64-битный ELF")
    if e_ident[5] != ELFDATA2LSB:
        raise ValueError("Не little-endian (ожидался x86-64)")

    return {
        'e_ident': e_ident,
        'e_type': e_type,
        'e_machine': e_machine,
        'e_version': e_version,
        'e_entry': e_entry,
        'e_phoff': e_phoff,
        'e_shoff': e_shoff,
        'e_flags': e_flags,
        'e_ehsize': e_ehsize,
        'e_phentsize': e_phentsize,
        'e_phnum': e_phnum,
        'e_shentsize': e_shentsize,
        'e_shnum': e_shnum,
        'e_shstrndx': e_shstrndx
    }


def read_section_headers(f, shoff, shnum):
    """Возвращает список словарей с заголовками секций."""
    f.seek(shoff)
    sections = []
    fmt = 'I I Q Q Q Q I I Q Q'
    for _ in range(shnum):
        data = f.read(64)
        vals = struct.unpack(fmt, data)
        sections.append({
            'sh_name': vals[0],
            'sh_type': vals[1],
            'sh_flags': vals[2],
            'sh_addr': vals[3],
            'sh_offset': vals[4],
            'sh_size': vals[5],
            'sh_link': vals[6],
            'sh_info': vals[7],
            'sh_addralign': vals[8],
            'sh_entsize': vals[9]
        })
    return sections


def read_program_headers(f, phoff, phnum):
    """Возвращает список словарей с программными заголовками."""
    f.seek(phoff)
    headers = []
    fmt = 'I I Q Q Q Q Q Q'
    for _ in range(phnum):
        data = f.read(56)
        vals = struct.unpack(fmt, data)
        headers.append({
            'p_type': vals[0],
            'p_flags': vals[1],
            'p_offset': vals[2],
            'p_vaddr': vals[3],
            'p_paddr': vals[4],
            'p_filesz': vals[5],
            'p_memsz': vals[6],
            'p_align': vals[7]
        })
    return headers


def get_section_name(f, shstrtab_offset, shstrtab_size, sh_name_offset):
    """Извлекает имя секции из таблицы строк."""
    f.seek(shstrtab_offset + sh_name_offset)
    name = b''
    while True:
        ch = f.read(1)
        if ch == b'\0' or ch == b'':
            break
        name += ch
    return name.decode('latin-1', errors='replace')


def get_flags_description(sh_flags, sh_type=0, sh_info=0):
    """
    Расшифровка флагов секции: W (запись), A (назнач), X (исполняемый), I (инфо).
    
    Для секций REL/RELA флаг 'I' устанавливается, если sh_info указывает
    на целевую секцию (sh_info > 0), как это делает readelf.
    """
    flags = []
    if sh_flags & 0x1: flags.append('W')  # WRITE
    if sh_flags & 0x2: flags.append('A')  # ALLOC
    if sh_flags & 0x4: flags.append('X')  # EXECINSTR
    if sh_flags & 0x8: flags.append('I')  # INFO (GNU extension)
    # Дополнительно: REL/RELA секции с sh_info > 0 получают флаг I
    if (sh_type == SHT_REL or sh_type == SHT_RELA) and sh_info > 0:
        if 'I' not in flags:
            flags.append('I')
    return ''.join(flags)


def is_section_in_segment(sec, ph):
    """
    Проверяет, принадлежит ли секция сегменту.
    Исключает секции с нулевым адресом (не загружаемые в память).
    """
    if sec['sh_size'] == 0:
        return False
    if sec['sh_addr'] == 0:
        return False
    if ph['p_memsz'] == 0:
        return False
    # Проверяем, что секция находится внутри сегмента
    return (sec['sh_addr'] >= ph['p_vaddr'] and 
            sec['sh_addr'] + sec['sh_size'] <= ph['p_vaddr'] + ph['p_memsz'])


# ---------- функции форматирования (на русском) ----------
def format_elf_header(hdr):
    """Возвращает строку с ELF-заголовком в стиле readelf -h."""
    lines = []
    lines.append("Заголовок ELF:")
    lines.append(f"  Magic:   {hdr['e_ident'].hex(' ')}")
    lines.append(f"  Класс:                             ELF64")
    
    if hdr['e_ident'][5] == 1:
        lines.append(f"  Данные:                            дополнение до 2, от младшего к старшему")
    else:
        lines.append(f"  Данные:                            дополнение до 2, от старшего к младшему")
    
    lines.append(f"  Version:                           {hdr['e_ident'][6]} (current)")
    lines.append(f"  OS/ABI:                            {OSABI_NAMES.get(hdr['e_ident'][7], 'Неизвестно')}")
    lines.append(f"  Версия ABI:                        {hdr['e_ident'][8]}")
    
    etype = ETYPE_NAMES.get(hdr['e_type'], 'UNKNOWN')
    lines.append(f"  Тип:                               {etype}")
    
    if hdr['e_machine'] == EM_X86_64:
        lines.append(f"  Машина:                            Advanced Micro Devices X86-64")
    else:
        lines.append(f"  Машина:                            0x{hdr['e_machine']:x}")
    
    lines.append(f"  Версия:                            0x{hdr['e_version']:x}")
    lines.append(f"  Адрес точки входа:                0x{hdr['e_entry']:x}")
    lines.append(f"  Начало заголовков программы:           {hdr['e_phoff']} (байт в файле)")
    lines.append(f"  Начало заголовков раздела:          {hdr['e_shoff']} (байт в файле)")
    lines.append(f"  Флаги:                             0x{hdr['e_flags']:x}")
    lines.append(f"  Size of this header:               {hdr['e_ehsize']} (bytes)")
    lines.append(f"  Size of program headers:           {hdr['e_phentsize']} (bytes)")
    lines.append(f"  Number of program headers:         {hdr['e_phnum']}")
    lines.append(f"  Size of section headers:           {hdr['e_shentsize']} (bytes)")
    lines.append(f"  Number of section headers:         {hdr['e_shnum']}")
    lines.append(f"  Section header string table index: {hdr['e_shstrndx']}")
    return '\n'.join(lines)


def format_sections(f, sections, shstrtab_offset, shstrtab_size):
    """Возвращает строку с таблицей секций в стиле readelf -S."""
    lines = []
    lines.append("\nЗаголовки разделов:")
    lines.append("  [Нм] Имя               Тип              Адрес             Смещение     Размер            Разм.Ent         Флаги  Ссылк Инфо  Выравн")
    
    for idx, sec in enumerate(sections):
        name = get_section_name(f, shstrtab_offset, shstrtab_size, sec['sh_name'])
        stype = SHT_NAMES.get(sec['sh_type'], f"0x{sec['sh_type']:x}")
        flags = get_flags_description(sec['sh_flags'], sec['sh_type'], sec['sh_info'])
        
        if idx == 0:
            # Пустая секция - специальный формат
            lines.append(f"  [{idx:2d}] {name:20s} {stype:16s} {sec['sh_addr']:016x}  {sec['sh_offset']:08x}")
            lines.append(f"       {sec['sh_size']:016x}  {sec['sh_entsize']:016x}            {sec['sh_link']:<6d}{sec['sh_info']:<6d}{sec['sh_addralign']:<8d}")
        else:
            flags_str = flags if flags else " "
            lines.append(f"  [{idx:2d}] {name:20s} {stype:16s} {sec['sh_addr']:016x}  {sec['sh_offset']:08x}")
            lines.append(f"       {sec['sh_size']:016x}  {sec['sh_entsize']:016x}  {flags_str:4s}     {sec['sh_link']:<6d}{sec['sh_info']:<6d}{sec['sh_addralign']:<8d}")
    
    # Добавляем легенду флагов
    lines.append("Обозначения флагов:")
    lines.append("  W (запись), A (назнач), X (исполняемый), M (слияние), S (строки),")
    lines.append("  I (инфо), L (порядок ссылок), O (требуется дополнительная работа ОС),")
    lines.append("  G (группа), T (TLS), C (сжат), x (неизвестно), o (специфич. для ОС),")
    lines.append("  E (исключён), D (mbind), l (большой), p (processor specific)")
    
    return '\n'.join(lines)


def format_program_headers(phdrs):
    """Возвращает строку с программными заголовками в стиле readelf -l."""
    lines = []
    lines.append("\nЗаголовки программы:")
    lines.append("  Тип            Смещ.              Вирт.адр           Физ.адр")
    lines.append("                 Рзм.фйл            Рзм.пм              Флаги  Выравн")
    
    for ph in phdrs:
        ptype = PT_NAMES.get(ph['p_type'], f"0x{ph['p_type']:x}")
        
        # Формируем флаги
        flags = ''
        if ph['p_flags'] & 4: flags += 'R'
        if ph['p_flags'] & 2: flags += 'W'
        if ph['p_flags'] & 1: flags += 'E'
        if not flags: flags = ' '
        
        lines.append(f"  {ptype:14s} 0x{ph['p_offset']:016x} 0x{ph['p_vaddr']:016x} 0x{ph['p_paddr']:016x}")
        lines.append(f"                 0x{ph['p_filesz']:016x} 0x{ph['p_memsz']:016x}  {flags:4s}    0x{ph['p_align']:x}")
    
    return '\n'.join(lines)


def format_segment_section_map(sections, phdrs, get_name_func):
    """Форматирует соответствие сегментов и секций."""
    lines = []
    lines.append("\n Соответствие раздел-сегмент:")
    lines.append("  Сегмент Разделы...")
    
    for pidx, ph in enumerate(phdrs):
        seg_sections = []
        for sidx, sec in enumerate(sections):
            if is_section_in_segment(sec, ph):
                name = get_name_func(sidx)
                if name:
                    seg_sections.append(name)
        
        if seg_sections:
            section_names = ' '.join(seg_sections)
            lines.append(f"   {pidx:02d}     {section_names}")
        else:
            lines.append(f"   {pidx:02d}     ")
    
    return '\n'.join(lines)


# ---------- главная функция ----------
def main():
    if len(sys.argv) != 2:
        print(f"Использование: {sys.argv[0]} <elf-файл>", flush=True)
        sys.exit(1)

    filename = sys.argv[1]
    
    try:
        with open(filename, 'rb') as f:
            # 1. ELF заголовок
            hdr = read_elf_header(f)
            if hdr['e_machine'] != EM_X86_64:
                print("Предупреждение: обнаружена не x86-64 архитектура, вывод может быть некорректным.", flush=True)
            print(format_elf_header(hdr), flush=True)

            # Читаем секции для использования в других блоках
            sections = []
            if hdr['e_shnum'] > 0:
                sections = read_section_headers(f, hdr['e_shoff'], hdr['e_shnum'])
            
            # Функция для получения имён секций (для маппинга)
            def get_sec_name(sidx):
                if sidx < len(sections):
                    shstrtab = sections[hdr['e_shstrndx']]
                    return get_section_name(f, shstrtab['sh_offset'], shstrtab['sh_size'], sections[sidx]['sh_name'])
                return '???'
            
            # Вывод секций
            if hdr['e_shnum'] > 0:
                shstrtab = sections[hdr['e_shstrndx']]
                print(format_sections(f, sections, shstrtab['sh_offset'], shstrtab['sh_size']), flush=True)
            else:
                print("\nФайл не содержит таблицы разделов.", flush=True)

            # Вывод программных заголовков
            if hdr['e_phnum'] > 0:
                phdrs = read_program_headers(f, hdr['e_phoff'], hdr['e_phnum'])
                print(format_program_headers(phdrs), flush=True)
                
                # Соответствие сегментов и секций
                print(format_segment_section_map(sections, phdrs, get_sec_name), flush=True)
            else:
                print("\nФайл не содержит программных заголовков.", flush=True)
    
    except Exception as e:
        print(f"Ошибка: {e}", file=sys.stderr, flush=True)
        sys.exit(1)


if __name__ == '__main__':
    main()