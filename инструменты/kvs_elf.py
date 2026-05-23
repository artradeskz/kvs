#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
kvs_elf.py - Генерация ELF заголовков для КВС
Содержит функции для создания ELF64 заголовка и программных заголовков
"""

import struct
from kvs_data import PAGE_SIZE, text_vaddr_base


class ELFHeader:
    """Генератор ELF64 заголовков"""
    
    # ELF константы
    EI_MAG0 = 0x7F
    EI_MAG1 = ord('E')
    EI_MAG2 = ord('L')
    EI_MAG3 = ord('F')
    EI_CLASS64 = 2
    EI_DATA2LSB = 1
    EI_VERSION = 1
    ET_EXEC = 2
    EM_X86_64 = 62
    EV_CURRENT = 1
    PT_LOAD = 1
    PF_R = 0x4
    PF_W = 0x2
    PF_X = 0x1
    
    def __init__(self):
        self.entry_point = 0  # будет заполнено позже
        
    def get_header_bytes(self):
        """Возвращает байты ELF заголовка"""
        # e_ident (16 байт)
        e_ident = bytes([
            self.EI_MAG0, self.EI_MAG1, self.EI_MAG2, self.EI_MAG3,  # magic
            self.EI_CLASS64,      # ELFCLASS64
            self.EI_DATA2LSB,     # ELFDATA2LSB
            self.EI_VERSION,      # EV_CURRENT
            0,                    # OS ABI (none)
            0,                    # ABI version
            0, 0, 0, 0, 0, 0, 0   # padding
        ])
        
        # Собираем заголовок
        header = bytearray(e_ident)
        header.extend(struct.pack('<H', self.ET_EXEC))      # e_type
        header.extend(struct.pack('<H', self.EM_X86_64))    # e_machine
        header.extend(struct.pack('<I', self.EV_CURRENT))   # e_version
        header.extend(struct.pack('<Q', self.entry_point))  # e_entry
        header.extend(struct.pack('<Q', 64))                # e_phoff (программные заголовки сразу после ELF)
        header.extend(struct.pack('<Q', 0))                 # e_shoff (нет секций)
        header.extend(struct.pack('<I', 0))                 # e_flags
        header.extend(struct.pack('<H', 64))                # e_ehsize
        header.extend(struct.pack('<H', 56))                # e_phentsize
        header.extend(struct.pack('<H', 2))                 # e_phnum (2 программных заголовка)
        header.extend(struct.pack('<H', 0))                 # e_shentsize
        header.extend(struct.pack('<H', 0))                 # e_shnum
        header.extend(struct.pack('<H', 0))                 # e_shstrndx
        
        return bytes(header)
    
    def set_entry_point(self, addr):
        """Устанавливает точку входа"""
        self.entry_point = addr


class ProgramHeaders:
    """Генератор программных заголовков ELF"""
    
    def __init__(self):
        self.text_offset = 0x1000
        self.text_vaddr = text_vaddr_base
        self.text_paddr = text_vaddr_base
        self.text_filesz = 0
        self.text_memsz = 0
        
        self.data_offset = 0x2000
        self.data_vaddr = 0
        self.data_paddr = 0
        self.data_filesz = 0
        self.data_memsz = 0
        
    def get_text_header_bytes(self):
        """Возвращает байты программного заголовка для TEXT сегмента"""
        header = bytearray()
        header.extend(struct.pack('<I', ELFHeader.PT_LOAD))      # p_type
        header.extend(struct.pack('<I', ELFHeader.PF_R | ELFHeader.PF_X))  # p_flags = RX
        header.extend(struct.pack('<Q', self.text_offset))      # p_offset
        header.extend(struct.pack('<Q', self.text_vaddr))       # p_vaddr
        header.extend(struct.pack('<Q', self.text_paddr))       # p_paddr
        header.extend(struct.pack('<Q', self.text_filesz))      # p_filesz
        header.extend(struct.pack('<Q', self.text_memsz))       # p_memsz
        header.extend(struct.pack('<Q', PAGE_SIZE))             # p_align
        return bytes(header)
    
    def get_data_header_bytes(self):
        """Возвращает байты программного заголовка для DATA сегмента"""
        header = bytearray()
        header.extend(struct.pack('<I', ELFHeader.PT_LOAD))      # p_type
        header.extend(struct.pack('<I', ELFHeader.PF_R | ELFHeader.PF_W))  # p_flags = RW
        header.extend(struct.pack('<Q', self.data_offset))      # p_offset
        header.extend(struct.pack('<Q', self.data_vaddr))       # p_vaddr
        header.extend(struct.pack('<Q', self.data_paddr))       # p_paddr
        header.extend(struct.pack('<Q', self.data_filesz))      # p_filesz
        header.extend(struct.pack('<Q', self.data_memsz))       # p_memsz
        header.extend(struct.pack('<Q', PAGE_SIZE))             # p_align
        return bytes(header)
    
    def set_text_sizes(self, filesz, memsz=None):
        """Устанавливает размеры TEXT сегмента"""
        self.text_filesz = filesz
        self.text_memsz = memsz if memsz is not None else filesz
    
    def set_data_sizes(self, filesz, memsz=None):
        """Устанавливает размеры DATA сегмента"""
        self.data_filesz = filesz
        self.data_memsz = memsz if memsz is not None else filesz
    
    def set_data_vaddr(self, vaddr):
        """Устанавливает виртуальный адрес DATA сегмента"""
        self.data_vaddr = vaddr
        self.data_paddr = vaddr


def generate_elf_bytes(entry_point, text_filesz, text_memsz, data_vaddr, data_filesz, data_memsz):
    """
    Генерирует полный ELF заголовок (ELF header + 2 program headers)
    Возвращает bytes
    """
    elf = ELFHeader()
    elf.set_entry_point(entry_point)
    
    ph = ProgramHeaders()
    ph.set_text_sizes(text_filesz, text_memsz)
    ph.set_data_sizes(data_filesz, data_memsz)
    ph.set_data_vaddr(data_vaddr)
    
    # Собираем всё вместе
    result = bytearray()
    result.extend(elf.get_header_bytes())      # 64 байта
    result.extend(ph.get_text_header_bytes())  # 56 байт
    result.extend(ph.get_data_header_bytes())  # 56 байт
    
    return bytes(result)


# Для обратной совместимости со старым кодом
def get_elf_header_bytes():
    """Возвращает ELF заголовок с заглушками (для первого прохода)"""
    elf = ELFHeader()
    return elf.get_header_bytes()


def get_text_phdr_bytes():
    """Возвращает программный заголовок TEXT с заглушками"""
    ph = ProgramHeaders()
    return ph.get_text_header_bytes()


def get_data_phdr_bytes():
    """Возвращает программный заголовок DATA с заглушками"""
    ph = ProgramHeaders()
    return ph.get_data_header_bytes()