#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Первый проход КВС (однопроходная версия с заглушками)
Генерирует CSV-таблицу напрямую из AST
- Неизвестные метки заменяются заглушками (0xCC) с пометкой в колонке 'уводящий_адрес'
- В колонке 'приводящая_метка' записываются имена меток, находящихся по данному адресу (через запятую)
- Колонка 'команда_со_значениями' оставлена пустой (для возможного расширения)
- Колонки 'рассчитанный_уводящий_адрес' и 'рассчитанный_байт' оставлены для второго прохода
"""

import sys
import csv

sys.path.insert(0, '.')
from kvs_data import PAGE_SIZE, text_vaddr_base, align_up
from kvs_encoder import encode_instruction

# ========== ГЛОБАЛЬНОЕ СОСТОЯНИЕ ==========
entries = []  # (segment, address, byte, target, source, label, source_with_values, calc_target, calc_byte)
current_address = 0
current_segment = '.header'
last_segment = None

vaddr_text = text_vaddr_base
vaddr_data = None
vaddr_bnd = None

text_buffer = bytearray()
data_buffer = bytearray()
bnd_size = 0

labels = {}  # имя метки -> адрес
label_sections = {}  # имя метки -> секция
symbols = {}  # имя константы -> значение

# Для сбора нескольких меток на один адрес
pending_labels = []  # список имён меток, ожидающих привязки к следующему байту

text_pos = 0
data_pos = 0

entry_point = "_start"
relocations = []


def reset_state():
    global entries, current_address, current_segment, last_segment
    global text_buffer, data_buffer, bnd_size, vaddr_data, vaddr_bnd
    global labels, label_sections, symbols, text_pos, data_pos, entry_point, relocations
    global pending_labels
    
    entries = []
    current_address = 0
    current_segment = '.header'
    last_segment = None
    text_buffer = bytearray()
    data_buffer = bytearray()
    bnd_size = 0
    vaddr_data = None
    vaddr_bnd = None
    labels = {}
    label_sections = {}
    symbols = {}
    text_pos = 0
    data_pos = 0
    entry_point = "_start"
    relocations = []
    pending_labels = []


def set_segment(segment: str):
    global current_segment
    current_segment = segment


def add_byte(value: int, source: str = "", target=None, labels_list=None):
    """Добавить один байт в текущую позицию"""
    global current_address, last_segment, pending_labels
    
    # Если есть отложенные метки, объединяем их через запятую
    effective_labels = ""
    if labels_list is not None and labels_list:
        effective_labels = ','.join(labels_list)
    elif pending_labels:
        effective_labels = ','.join(pending_labels)
    
    show_segment = current_segment if current_segment != last_segment else None
    if show_segment:
        last_segment = current_segment
    
    entries.append((
        show_segment if show_segment else "",  # segment
        current_address,                       # address
        value & 0xFF,                          # byte
        target if target else "",              # target (уводящий_адрес)
        source,                                # source (исходная_команда)
        effective_labels,                      # label (приводящая_метка) - несколько через запятую
        "",                                    # source_with_values (команда_со_значениями) - всегда пусто
        "",                                    # calc_target
        ""                                     # calc_byte
    ))
    current_address += 1
    
    # После добавления байта сбрасываем отложенные метки
    if pending_labels:
        pending_labels = []


def add_bytes(values, source: str = "", target=None):
    for i, v in enumerate(values):
        add_byte(v, source if i == 0 else "", target if i == 0 else None)


def add_word16(value: int, source: str = "", target=None):
    """Добавить 16-битное слово (little-endian)"""
    add_bytes([
        (value >> 0) & 0xFF,
        (value >> 8) & 0xFF,
    ], source, target)


def add_word32(value: int, source: str = "", target=None):
    """Добавить 32-битное слово (little-endian)"""
    add_bytes([
        (value >> 0) & 0xFF,
        (value >> 8) & 0xFF,
        (value >> 16) & 0xFF,
        (value >> 24) & 0xFF,
    ], source, target)


def add_word64(value: int, source: str = "", target=None):
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
    ], source, target)


def align_to(alignment: int):
    global current_address, pending_labels
    padding = (alignment - (current_address % alignment)) % alignment
    if padding > 0:
        pending_labels = []
        current_address += padding


def unescape_string(s):
    result = []
    i = 0
    while i < len(s):
        if s[i] == '\\' and i + 1 < len(s):
            if s[i + 1] == 'n':
                result.append('\n')
            elif s[i + 1] == 't':
                result.append('\t')
            elif s[i + 1] == 'r':
                result.append('\r')
            else:
                result.append(s[i + 1])
            i += 2
        else:
            result.append(s[i])
            i += 1
    return ''.join(result)


def generate_elf_header():
    # EI_MAGIC
    add_bytes([0x7F, 0x45, 0x4C, 0x46], "ELF magic")
    # EI_CLASS, EI_DATA, EI_VERSION
    add_byte(2, "ELFCLASS64")
    add_byte(1, "ELFDATA2LSB")
    add_byte(1, "ELF version")
    # EI_OSABI, EI_ABIVERSION
    add_byte(0, "OS ABI")
    add_byte(0, "ABI version")
    # EI_PAD
    add_bytes([0] * 7, "Padding")
    
    # e_type (2 байта)
    add_word16(2, "e_type = ET_EXEC")
    # e_machine (2 байта)
    add_word16(62, "e_machine = EM_X86_64")
    # e_version (4 байта)
    add_word32(1, "e_version")
    # e_entry (8 байт, заглушка)
    add_word64(0, "e_entry (stub)")
    # e_phoff (8 байт)
    add_word64(64, "e_phoff")
    # e_shoff (8 байт)
    add_word64(0, "e_shoff = 0")
    # e_flags (4 байта)
    add_word32(0, "e_flags")
    # e_ehsize (2 байта)
    add_word16(64, "e_ehsize")
    # e_phentsize (2 байта)
    add_word16(56, "e_phentsize")
    # e_phnum (2 байта)
    add_word16(2, "e_phnum = 2")
    # e_shentsize (2 байта)
    add_word16(0, "e_shentsize = 0")
    # e_shnum (2 байта)
    add_word16(0, "e_shnum = 0")
    # e_shstrndx (2 байта)
    add_word16(0, "e_shstrndx")


def generate_program_headers():
    # Program Header 1: TEXT (RX)
    add_word32(1, "p_type = PT_LOAD")
    add_word32(5, "p_flags = RX")
    add_word64(0, "p_offset (text stub)")
    add_word64(vaddr_text, "p_vaddr (text)")
    add_word64(vaddr_text, "p_paddr (text)")
    add_word64(0, "p_filesz (text stub)")
    add_word64(0, "p_memsz (text stub)")
    add_word64(PAGE_SIZE, "p_align")
    
    # Program Header 2: DATA (RW)
    add_word32(1, "p_type = PT_LOAD")
    add_word32(6, "p_flags = RW")
    add_word64(0, "p_offset (data stub)")
    add_word64(0, "p_vaddr (data stub)")
    add_word64(0, "p_paddr (data stub)")
    add_word64(0, "p_filesz (data stub)")
    add_word64(0, "p_memsz (data stub)")
    add_word64(PAGE_SIZE, "p_align")


def read_ast(input_file):
    with open(input_file, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f]


def parse_ast_line(line):
    if not line:
        return None, {}
    
    line_type = line.split(':')[0]
    
    if line_type == "INSTR":
        first = line.find(':')
        second = line.find(':', first + 1)
        third = line.find(':', second + 1)
        
        if first == -1 or second == -1 or third == -1:
            return "INSTR", {}
        
        mnemonic = line[first + 1:second]
        section = line[second + 1:third]
        operands_str = line[third + 1:]
        
        operands = operands_str.split(',') if operands_str else []
        
        return "INSTR", {
            'mnemonic': mnemonic,
            'section': section,
            'operands': operands
        }
    
    elif line_type == "DIRECTIVE":
        parts = line.split(':')
        directive = parts[1] if len(parts) > 1 else ""
        
        if directive in ('.текст', '.данные', '.бнд'):
            return "DIRECTIVE", {'directive': directive}
        elif directive == '.глобал':
            return "DIRECTIVE", {'directive': directive, 'label': parts[2] if len(parts) > 2 else ""}
        elif directive in ('.строка', '.строка_нуль'):
            return "DIRECTIVE", {
                'directive': directive,
                'section': parts[2] if len(parts) > 2 else "",
                'string': parts[3] if len(parts) > 3 else ""
            }
        elif directive == '.константа':
            return "DIRECTIVE", {
                'directive': directive,
                'name': parts[2] if len(parts) > 2 else "",
                'value': parts[3] if len(parts) > 3 else ""
            }
        elif directive == '.байт':
            return "DIRECTIVE", {
                'directive': directive,
                'section': parts[2] if len(parts) > 2 else "",
                'bytes': parts[3] if len(parts) > 3 else ""
            }
        elif directive in ('.резб', '.резс', '.рездс', '.резкс'):
            return "DIRECTIVE", {
                'directive': directive,
                'section': parts[2] if len(parts) > 2 else "",
                'count': parts[3] if len(parts) > 3 else "0"
            }
        else:
            return "DIRECTIVE", {'directive': directive}
    
    elif line_type == "LABEL":
        parts = line.split(':')
        return "LABEL", {
            'name': parts[1] if len(parts) > 1 else "",
            'section': parts[2] if len(parts) > 2 else ""
        }
    
    return line_type, {}


def get_stub_size(mnemonic, operands):
    if mnemonic == "переместить_имм" and len(operands) >= 2:
        reg = operands[0]
        if reg in ('раикс', 'рбикс', 'рсикс', 'рдикс', 'рсипи', 'рбипи', 'рсиай', 'рдиай',
                   'р8', 'р9', 'р10', 'р11', 'р12', 'р13', 'р14', 'р15'):
            return 10
        elif reg in ('еаикс', 'ебикс', 'есикс', 'едикс'):
            return 7
        else:
            return 2
    elif mnemonic in ("переход", "вызвать"):
        return 5
    elif mnemonic.startswith("короткий_переход"):
        return 2
    elif mnemonic.startswith("переход_если"):
        return 6
    elif mnemonic.startswith("короткий_переход_если"):
        return 2
    elif mnemonic in ("загрузить", "сохранить", "загрузить_адрес"):
        return 7
    return 1


def has_unresolved_labels(operands):
    for op in operands:
        if not op:
            continue
        if op in ('раикс', 'рбикс', 'рсикс', 'рдикс', 'рсипи', 'рбипи', 'рсиай', 'рдиай',
                  'р8', 'р9', 'р10', 'р11', 'р12', 'р13', 'р14', 'р15',
                  'еаикс', 'ебикс', 'есикс', 'едикс',
                  'аикс', 'бикс', 'сикс', 'дикс',
                  'ал', 'бл', 'кл', 'дл'):
            continue
        if op.startswith('[') and op.endswith(']'):
            inner = op[1:-1]
            if inner in ('раикс', 'рбикс', 'рсикс', 'рдикс', 'рсипи', 'рбипи', 'рсиай', 'рдиай'):
                continue
            if inner in labels:
                continue
            if inner.isdigit() or (inner.startswith('0x')):
                continue
            return True
        elif op in labels:
            continue
        elif op.isdigit() or (op.startswith('0x')):
            continue
        else:
            if op in symbols:
                continue
            return True
    return False


def get_unresolved_labels(operands):
    unresolved = []
    for op in operands:
        if not op:
            continue
        if op.startswith('[') and op.endswith(']'):
            inner = op[1:-1]
            if inner not in labels and not inner.isdigit() and not (inner.startswith('0x')):
                if inner not in ('раикс', 'рбикс', 'рсикс', 'рдикс', 'рсипи', 'рбипи', 'рсиай', 'рдиай'):
                    if inner not in symbols:
                        unresolved.append(inner)
        elif op not in labels and not op.isdigit() and not (op.startswith('0x')):
            if op not in ('раикс', 'рбикс', 'рсикс', 'рдикс', 'рсипи', 'рбипи', 'рсиай', 'рдиай',
                          'еаикс', 'ебикс', 'есикс', 'едикс',
                          'аикс', 'бикс', 'сикс', 'дикс',
                          'ал', 'бл', 'кл', 'дл'):
                if op not in symbols:
                    unresolved.append(op)
    return unresolved


def process_ast_line(line):
    global text_pos, data_pos, vaddr_data, vaddr_bnd, bnd_size
    global text_buffer, data_buffer, entry_point, symbols, pending_labels
    
    line_type, fields = parse_ast_line(line)
    
    if line_type == "DIRECTIVE":
        directive = fields.get('directive', '')
        
        if directive == '.текст':
            set_segment('.text')
        
        elif directive == '.данные':
            set_segment('.data')
            align_to(PAGE_SIZE)
        
        elif directive == '.бнд':
            set_segment('.bss')
        
        elif directive == '.глобал':
            entry_point = fields.get('label', '_start')
        
        elif directive == '.константа':
            name = fields.get('name', '')
            value_str = fields.get('value', '')
            if value_str.startswith('0x') or value_str.startswith('0X'):
                value = int(value_str, 16)
            else:
                value = int(value_str)
            symbols[name] = value
            print(f"  константа: {name} = {value}")
        
        elif directive in ('.строка', '.строка_нуль'):
            s = fields.get('string', '')
            real_s = unescape_string(s)
            bstring = real_s.encode('utf-8')
            if directive == '.строка_нуль':
                bstring += b'\x00'
            
            source = f'{directive} "{s}"'
            
            for i, byte in enumerate(bstring):
                labels_list = pending_labels if i == 0 else None
                add_byte(byte, source if i == 0 else "", None, labels_list)
                data_buffer.append(byte)
                if labels_list:
                    pending_labels = []
            data_pos += len(bstring)
        
        elif directive == '.байт':
            bytes_str = fields.get('bytes', '')
            if bytes_str:
                byte_values = bytes_str.split(',')
                source = f'.байт {bytes_str}'
                bstring = bytearray()
                for byte_str in byte_values:
                    byte_str = byte_str.strip()
                    if byte_str.startswith('0x'):
                        val = int(byte_str, 16)
                    else:
                        val = int(byte_str)
                    bstring.append(val & 0xFF)
                
                for i, byte in enumerate(bstring):
                    labels_list = pending_labels if i == 0 else None
                    add_byte(byte, source if i == 0 else "", None, labels_list)
                    data_buffer.append(byte)
                    if labels_list:
                        pending_labels = []
                data_pos += len(bstring)
        
        elif directive in ('.резб', '.резс', '.рездс', '.резкс'):
            count = int(fields.get('count', '0'))
            multiplier = {'резб': 1, 'резс': 2, 'рездс': 4, 'резкс': 8}
            bnd_size += count * multiplier.get(directive, 1)
    
    elif line_type == "LABEL":
        label_name = fields.get('name', '')
        sec = fields.get('section', '')
        
        if sec == '.text':
            addr = vaddr_text + text_pos
            labels[label_name] = addr
            label_sections[label_name] = sec
            if label_name not in pending_labels:
                pending_labels.append(label_name)
        
        elif sec == '.data':
            if vaddr_data is None:
                vaddr_data = align_up(vaddr_text + text_pos, PAGE_SIZE)
            addr = vaddr_data + data_pos
            labels[label_name] = addr
            label_sections[label_name] = sec
            if label_name not in pending_labels:
                pending_labels.append(label_name)
        
        elif sec == '.бнд':
            if vaddr_bnd is None:
                vaddr_bnd = align_up(vaddr_data + data_pos, PAGE_SIZE)
            addr = vaddr_bnd + bnd_size
            labels[label_name] = addr
            label_sections[label_name] = sec
            if label_name not in pending_labels:
                pending_labels.append(label_name)
        
        else:
            addr = current_address
            labels[label_name] = addr
            label_sections[label_name] = sec
            if label_name not in pending_labels:
                pending_labels.append(label_name)
    
    elif line_type == "INSTR":
        mnemonic = fields.get('mnemonic', '')
        sec = fields.get('section', '')
        operands = fields.get('operands', [])
        
        source = f"{mnemonic} {', '.join(operands)}" if operands else mnemonic
        
        source_with_values = ""
        
        if has_unresolved_labels(operands):
            stub_size = get_stub_size(mnemonic, operands)
            unresolved = get_unresolved_labels(operands)
            reloc_text = f"ЗАГЛУШКА {', '.join(unresolved)}"
            
            relocations.append({
                'address': current_address,
                'size': stub_size,
                'labels': unresolved,
                'source': source,
                'mnemonic': mnemonic
            })
            
            for i in range(stub_size):
                labels_list = pending_labels if i == 0 else None
                add_byte(0xCC, source if i == 0 else "", reloc_text if i == 0 else None, labels_list)
                if labels_list:
                    pending_labels = []
            
            if sec == '.text':
                text_buffer.extend([0xCC] * stub_size)
                text_pos += stub_size
            else:
                data_buffer.extend([0xCC] * stub_size)
                data_pos += stub_size
        else:
            try:
                if sec == '.text':
                    current_pos = text_pos
                else:
                    current_pos = data_pos
                
                encoded = encode_instruction(
                    mnemonic, operands, labels, label_sections, symbols,
                    vaddr_text, vaddr_data if vaddr_data else 0,
                    current_pos, vaddr_bnd if vaddr_bnd else 0
                )
                
                for i, byte in enumerate(encoded):
                    labels_list = pending_labels if i == 0 else None
                    add_byte(byte, source if i == 0 else "", None, labels_list)
                    if labels_list:
                        pending_labels = []
                
                if sec == '.text':
                    text_buffer.extend(encoded)
                    text_pos += len(encoded)
                else:
                    data_buffer.extend(encoded)
                    data_pos += len(encoded)
                    
            except Exception as e:
                print(f"Ошибка кодирования {source}: {e}", file=sys.stderr)
                labels_list = pending_labels
                add_byte(0xCC, source, None, f"ОШИБКА: {e}", labels_list)
                pending_labels = []
                
                if sec == '.text':
                    text_buffer.append(0xCC)
                    text_pos += 1
                else:
                    data_buffer.append(0xCC)
                    data_pos += 1


def finalize_headers():
    global entries
    
    text_offset = 0x1000
    data_offset = 0x2000
    
    text_filesz = len(text_buffer)
    text_memsz = len(text_buffer)
    
    data_filesz = len(data_buffer)
    data_memsz = len(data_buffer) + bnd_size
    
    vaddr_data_final = align_up(vaddr_text + text_filesz, PAGE_SIZE)
    entry_point_addr = labels.get(entry_point, vaddr_text)
    
    i = 0
    while i < len(entries):
        segment, addr, byte, target, source, label, source_with_values, calc_target, calc_byte = entries[i]
        
        # e_entry - 8 байт
        if 'e_entry (stub)' in source:
            new_bytes = [(entry_point_addr >> j*8) & 0xFF for j in range(8)]
            for j, nb in enumerate(new_bytes):
                entries[i + j] = (segment, addr + j, nb, target, 
                                  f"e_entry = 0x{entry_point_addr:x}", 
                                  label if j == 0 else "", 
                                  "", "", 
                                  f"0x{nb:02x}")
            i += 8
            continue
        
        # p_offset (text) - 8 байт
        elif 'p_offset (text stub)' in source:
            new_bytes = [(text_offset >> j*8) & 0xFF for j in range(8)]
            for j, nb in enumerate(new_bytes):
                entries[i + j] = (segment, addr + j, nb, target, 
                                  f"p_offset (text) = 0x{text_offset:x}", 
                                  label if j == 0 else "", 
                                  "", "", 
                                  f"0x{nb:02x}")
            i += 8
            continue
        
        # p_filesz (text) - 8 байт
        elif 'p_filesz (text stub)' in source:
            new_bytes = [(text_filesz >> j*8) & 0xFF for j in range(8)]
            for j, nb in enumerate(new_bytes):
                entries[i + j] = (segment, addr + j, nb, target, 
                                  f"p_filesz (text) = {text_filesz}", 
                                  label if j == 0 else "", 
                                  "", "", 
                                  f"0x{nb:02x}")
            i += 8
            continue
        
        # p_memsz (text) - 8 байт
        elif 'p_memsz (text stub)' in source:
            new_bytes = [(text_memsz >> j*8) & 0xFF for j in range(8)]
            for j, nb in enumerate(new_bytes):
                entries[i + j] = (segment, addr + j, nb, target, 
                                  f"p_memsz (text) = {text_memsz}", 
                                  label if j == 0 else "", 
                                  "", "", 
                                  f"0x{nb:02x}")
            i += 8
            continue
        
        # p_offset (data) - 8 байт
        elif 'p_offset (data stub)' in source:
            new_bytes = [(data_offset >> j*8) & 0xFF for j in range(8)]
            for j, nb in enumerate(new_bytes):
                entries[i + j] = (segment, addr + j, nb, target, 
                                  f"p_offset (data) = 0x{data_offset:x}", 
                                  label if j == 0 else "", 
                                  "", "", 
                                  f"0x{nb:02x}")
            i += 8
            continue
        
        # p_vaddr (data) - 8 байт
        elif 'p_vaddr (data stub)' in source:
            new_bytes = [(vaddr_data_final >> j*8) & 0xFF for j in range(8)]
            for j, nb in enumerate(new_bytes):
                entries[i + j] = (segment, addr + j, nb, target, 
                                  f"p_vaddr (data) = 0x{vaddr_data_final:x}", 
                                  label if j == 0 else "", 
                                  "", "", 
                                  f"0x{nb:02x}")
            i += 8
            continue
        
        # p_paddr (data) - 8 байт
        elif 'p_paddr (data stub)' in source:
            new_bytes = [(vaddr_data_final >> j*8) & 0xFF for j in range(8)]
            for j, nb in enumerate(new_bytes):
                entries[i + j] = (segment, addr + j, nb, target, 
                                  f"p_paddr (data) = 0x{vaddr_data_final:x}", 
                                  label if j == 0 else "", 
                                  "", "", 
                                  f"0x{nb:02x}")
            i += 8
            continue
        
        # p_filesz (data) - 8 байт
        elif 'p_filesz (data stub)' in source:
            new_bytes = [(data_filesz >> j*8) & 0xFF for j in range(8)]
            for j, nb in enumerate(new_bytes):
                entries[i + j] = (segment, addr + j, nb, target, 
                                  f"p_filesz (data) = {data_filesz}", 
                                  label if j == 0 else "", 
                                  "", "", 
                                  f"0x{nb:02x}")
            i += 8
            continue
        
        # p_memsz (data) - 8 байт
        elif 'p_memsz (data stub)' in source:
            new_bytes = [(data_memsz >> j*8) & 0xFF for j in range(8)]
            for j, nb in enumerate(new_bytes):
                entries[i + j] = (segment, addr + j, nb, target, 
                                  f"p_memsz (data) = {data_memsz}", 
                                  label if j == 0 else "", 
                                  "", "", 
                                  f"0x{nb:02x}")
            i += 8
            continue
        
        i += 1


def save_to_csv(filename: str):
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f, delimiter=';')
        writer.writerow(['сегмент', 'адрес', 'байт', 'приводящая_метка', 'уводящий_адрес', 
                         'исходная_команда', 'команда_со_значениями',
                         'рассчитанный_уводящий_адрес', 'рассчитанный_байт'])
        
        for segment, addr, byte, target, source, label, source_with_values, calc_target, calc_byte in entries:
            writer.writerow([
                segment,
                f"0x{addr:08x}",
                f"0x{byte:02x}",
                label,
                target,
                source,
                source_with_values,
                calc_target,
                calc_byte
            ])


def main():
    if len(sys.argv) != 3:
        print("Использование: python kvs_pass1.py <вход.аст> <выход.csv>")
        sys.exit(1)
    
    ast_file = sys.argv[1]
    csv_file = sys.argv[2]
    
    reset_state()
    
    set_segment('.header')
    generate_elf_header()
    generate_program_headers()
    align_to(PAGE_SIZE)
    
    ast_lines = read_ast(ast_file)
    for line in ast_lines:
        process_ast_line(line)
    
    finalize_headers()
    save_to_csv(csv_file)
    
    vaddr_data_final = align_up(vaddr_text + len(text_buffer), PAGE_SIZE)
    vaddr_bnd_final = align_up(vaddr_data_final + len(data_buffer), PAGE_SIZE)
    
    print(f"\n=== Первый проход (однопроходная генерация с заглушками) ===")
    print(f"  .text: {len(text_buffer)} байт, виртуальный адрес=0x{vaddr_text:x}")
    print(f"  .data: {len(data_buffer)} байт, виртуальный адрес=0x{vaddr_data_final:x}")
    print(f"  .bnd:  {bnd_size} байт, виртуальный адрес=0x{vaddr_bnd_final:x}")
    print(f"  точка входа: {entry_point} = 0x{labels.get(entry_point, vaddr_text):x}")
    print(f"  меток: {len(labels)}")
    print(f"  констант: {len(symbols)}")
    print(f"  релокаций: {len(relocations)}")
    print(f"  записей в CSV: {len(entries)}")
    print(f"  CSV сохранен: {csv_file}")


if __name__ == "__main__":
    main()