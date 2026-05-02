#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Сборщик ELF из CSV
"""

import sys
import struct
import os
sys.path.insert(0, '.')
from kvs_data import PAGE_SIZE, align_up

def read_csv(input_file, vaddr_text, vaddr_data, text_size, data_size):
    """Загружает байты из CSV используя точные виртуальные адреса"""
    text_bytes = bytearray(text_size)  # точный размер из pass1
    data_bytes = bytearray(data_size)
    
    with open(input_file, 'r', encoding='utf-8') as f:
        next(f)  # Пропускаем заголовок
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(';')
            if len(parts) < 2:
                continue
            addr_str = parts[0]
            byte_str = parts[1]
            
            try:
                addr = int(addr_str, 16)
                byte_val = int(byte_str, 16)
            except ValueError:
                continue
            
            # Определяем секцию по адресу
            if addr >= vaddr_data:
                offset = addr - vaddr_data
                if 0 <= offset < data_size:
                    data_bytes[offset] = byte_val
            elif addr >= vaddr_text:
                offset = addr - vaddr_text
                if 0 <= offset < text_size:
                    text_bytes[offset] = byte_val
    
    return text_bytes, data_bytes

def read_pass1(input_file):
    data = {}
    labels = {}
    
    with open(input_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(':')
            if parts[0] == "PARAM":
                key = parts[1]
                value = parts[2]
                if value.isdigit():
                    value = int(value)
                data[key] = value
            elif parts[0] == "LABEL":
                label = parts[1]
                pos = int(parts[3])
                labels[label] = pos
    
    return data, labels

def create_elf(text_bytes, data_bytes, pass1_data, labels, output_file):
    vaddr_text = pass1_data.get("vaddr_text", 0x401000)
    text_size = pass1_data.get("text_size", len(text_bytes))
    # Вычисляем vaddr_data динамически, как в kvs_8
    vaddr_data = align_up(vaddr_text + text_size, PAGE_SIZE)
    
    offset_text = pass1_data.get("offset_text", 0x1000)
    offset_data = align_up(offset_text + len(text_bytes), PAGE_SIZE)
    offset_comment = pass1_data.get("offset_comment", align_up(offset_data + len(data_bytes), 1))
    shstrtab_offset = pass1_data.get("shstrtab_offset", align_up(offset_comment + 32, 8))
    shdr_offset = pass1_data.get("shdr_offset", align_up(shstrtab_offset + 32, 16))
    entry_point_name = pass1_data.get("entry_point", "_start")
    
    entry_addr = vaddr_text + labels.get(entry_point_name, 0)
    
    comment_content = "Сборщик КВС".encode('utf-8') + b'\x00'
    shstrtab_content = b"\x00.text\x00.data\x00.comment\x00.shstrtab\x00"
    
    elf_header_size = 64
    ph_size = 56
    ph_num = 3
    shdr_size = 64
    shdr_num = 5
    
    file_size = shdr_offset + shdr_num * shdr_size
    elf_data = bytearray(file_size)
    
    # ELF header
    e_ident = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    elf_header = struct.pack(
        '<16sHHIQQQIHHHHHH',
        e_ident, 2, 0x3e, 1, entry_addr, elf_header_size, shdr_offset,
        0, elf_header_size, ph_size, ph_num, shdr_size, shdr_num, 4
    )
    elf_data[0:64] = elf_header
    
    def phdr(p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz):
        return struct.pack('<IIQQQQQQ',
            p_type, p_flags, p_offset, p_vaddr, p_vaddr,
            p_filesz, p_memsz, PAGE_SIZE
        )
    
    ph0 = phdr(1, 4, 0, 0x400000, elf_header_size + ph_num * ph_size, PAGE_SIZE)
    ph1 = phdr(1, 5, offset_text, vaddr_text, len(text_bytes), align_up(len(text_bytes), PAGE_SIZE))
    ph2 = phdr(1, 6, offset_data, vaddr_data, len(data_bytes), align_up(len(data_bytes), PAGE_SIZE))
    
    phdrs = ph0 + ph1 + ph2
    elf_data[elf_header_size : elf_header_size + len(phdrs)] = phdrs
    
    elf_data[offset_text : offset_text + len(text_bytes)] = text_bytes
    elf_data[offset_data : offset_data + len(data_bytes)] = data_bytes
    elf_data[offset_comment : offset_comment + len(comment_content)] = comment_content
    elf_data[shstrtab_offset : shstrtab_offset + len(shstrtab_content)] = shstrtab_content
    
    def shdr(name_idx, sh_type, flags, addr, offset, size, addralign=1):
        return struct.pack('<IIQQQQIIQQ',
            name_idx, sh_type, flags, addr, offset, size,
            0, 0, addralign, 0
        )
    
    sh0 = shdr(0, 0, 0, 0, 0, 0)
    sh1 = shdr(1, 1, 6, vaddr_text, offset_text, len(text_bytes), 16)
    sh2 = shdr(7, 1, 3, vaddr_data, offset_data, len(data_bytes), 8)
    sh3 = shdr(13, 1, 0, 0, offset_comment, len(comment_content), 1)
    sh4 = shdr(22, 3, 0, 0, shstrtab_offset, len(shstrtab_content), 1)
    
    shdrs = sh0 + sh1 + sh2 + sh3 + sh4
    elf_data[shdr_offset : shdr_offset + len(shdrs)] = shdrs
    
    with open(output_file, "wb") as f:
        f.write(elf_data)
    
    os.chmod(output_file, 0o755)
    
    print(f"Сборщик: ELF-файл создан: {output_file}")
    print(f"  .text: {len(text_bytes)} байт, адрес: 0x{vaddr_text:x}")
    print(f"  .data: {len(data_bytes)} байт, адрес: 0x{vaddr_data:x}")
    print(f"  Расстояние между секциями: 0x{vaddr_data - vaddr_text:x} байт")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Использование: python kvs_builder.py <вход.csv> <вход.проход1> <выход.elf>")
        sys.exit(1)
    
    pass1_data, labels = read_pass1(sys.argv[2])
    vaddr_text = pass1_data["vaddr_text"]
    text_size = pass1_data["text_size"]
    data_size = pass1_data["data_size"]
    
    # Вычисляем vaddr_data как в kvs_8
    vaddr_data = align_up(vaddr_text + text_size, PAGE_SIZE)
    
    text_bytes, data_bytes = read_csv(sys.argv[1], vaddr_text, vaddr_data, text_size, data_size)
    create_elf(text_bytes, data_bytes, pass1_data, labels, sys.argv[3])