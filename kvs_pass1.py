#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Первый проход КВС
Вычисляет размеры секций и адреса меток
"""

import sys
sys.path.insert(0, '.')
from kvs_data import PAGE_SIZE, text_vaddr_base, data_vaddr_base, align_up

def unescape_string(s):
    """Преобразует escape-последовательности в реальные символы"""
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
                result.append(s[i])
                result.append(s[i + 1])
            i += 2
        else:
            result.append(s[i])
            i += 1
    return ''.join(result)

def read_ast(input_file):
    ast_lines = []
    with open(input_file, 'r', encoding='utf-8') as f:
        for line in f:
            ast_lines.append(line.strip())
    return ast_lines

class Pass1:
    def __init__(self):
        self.labels = {}
        self.label_sections = {}
        self.symbols = {}
        self.position = {".text": 0, ".data": 0}
        self.current_section = ".text"
        self.entry_point = "_start"
        
    def process_line(self, line):
        parts = line.split(':')
        line_type = parts[0]
        
        if line_type == "DIRECTIVE":
            directive = parts[1]
            if directive == '.текст':
                self.current_section = ".text"
            elif directive == '.данные':
                self.current_section = ".data"
            elif directive == '.глобал':
                self.entry_point = parts[2]
            elif directive in ('.строка_нуль', '.строка'):
                s = parts[3] if len(parts) > 3 else ""
                real_s = unescape_string(s)
                bstring = real_s.encode('utf-8')
                add_null = (directive == '.строка_нуль')
                size = len(bstring) + (1 if add_null else 0)
                self.position[".data"] += size
            elif directive == '.константа':
                name = parts[2]
                value = parts[3]
                if value.isdigit():
                    self.symbols[name] = int(value)
                elif value.startswith('0x'):
                    self.symbols[name] = int(value, 16)
                else:
                    self.symbols[name] = 0
            elif directive == '.байт':
                sec = parts[2]
                if len(parts) > 3 and parts[3]:
                    num_bytes = len(parts[3].split(','))
                    self.position[sec] += num_bytes
                    
        elif line_type == "LABEL":
            label_name = parts[1]
            sec = parts[2]
            self.labels[label_name] = self.position[sec]
            self.label_sections[label_name] = sec
            
        elif line_type == "INSTR":
            mnemonic = parts[1]
            sec = parts[2]
            size = self.estimate_size(mnemonic)
            self.position[sec] += size
    
    def estimate_size(self, mnemonic):
        size_map = {
            "переместить_имм": 10,
            "сравнить_с": 7,
            "переход": 5,
            "переход_если_равно": 6,
            "переход_если_неравно": 6,
            "переход_если_ноль": 6,
            "переход_если_не_ноль": 6,
            "переход_если_меньше": 6,
            "переход_если_больше": 6,
            "переход_если_меньше_или_равно": 6,
            "переход_если_больше_или_равно": 6,
            "переход_если_перенос": 6,
            "переход_если_нет_переноса": 6,
            "вызов_системы": 2,
            "нет_операции": 1,
            "короткий_переход": 2,
            "короткий_переход_если_равно": 2,
            "короткий_переход_если_неравно": 2,
            "короткий_переход_если_меньше": 2,
            "короткий_переход_если_больше": 2,
            "короткий_переход_если_меньше_или_равно": 2,
            "короткий_переход_если_больше_или_равно": 2,
            "короткий_переход_если_перенос": 2,
            "короткий_переход_если_нет_переноса": 2,
            "короткий_переход_если_ноль": 2,
            "короткий_переход_если_не_ноль": 2,
            "сравнить": 3,
            "проверить": 3,
            "вычесть": 3,
            "прибавить": 3,
            "увеличить": 3,
            "уменьшить": 3,
        }
        return size_map.get(mnemonic, 3)
    
    def calculate_layout(self):
        text_size = self.position[".text"]
        data_size = self.position[".data"]
        
        elf_header_size = 64
        ph_size = 56
        ph_num = 3
        ph_table_size = ph_num * ph_size
        
        offset_text = align_up(elf_header_size + ph_table_size, PAGE_SIZE)
        offset_data = align_up(offset_text + text_size, PAGE_SIZE)
        vaddr_text = text_vaddr_base
        vaddr_data = align_up(vaddr_text + text_size, PAGE_SIZE)
        
        comment_size = len("Сборщик КВС".encode('utf-8')) + 1
        offset_comment = align_up(offset_data + data_size, 1)
        
        shstrtab_size = len(b"\x00.text\x00.data\x00.comment\x00.shstrtab\x00")
        shstrtab_offset = align_up(offset_comment + comment_size, 8)
        shdr_offset = align_up(shstrtab_offset + shstrtab_size, 16)
        
        return {
            "text_size": text_size,
            "data_size": data_size,
            "offset_text": offset_text,
            "offset_data": offset_data,
            "vaddr_text": vaddr_text,
            "vaddr_data": vaddr_data,
            "offset_comment": offset_comment,
            "comment_size": comment_size,
            "shstrtab_offset": shstrtab_offset,
            "shstrtab_size": shstrtab_size,
            "shdr_offset": shdr_offset,
            "entry_point": self.entry_point,
        }

def write_pass1(pass1_data, labels, label_sections, symbols, output_file):
    with open(output_file, 'w', encoding='utf-8') as f:
        for key, value in pass1_data.items():
            f.write(f"PARAM:{key}:{value}\n")
        for label, pos in labels.items():
            sec = label_sections.get(label, ".text")
            f.write(f"LABEL:{label}:{sec}:{pos}\n")
        for name, value in symbols.items():
            f.write(f"SYMBOL:{name}:{value}\n")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Использование: python kvs_pass1.py <вход.аст> <выход.проход1>")
        sys.exit(1)
    
    ast_lines = read_ast(sys.argv[1])
    pass1 = Pass1()
    for line in ast_lines:
        pass1.process_line(line)
    
    layout = pass1.calculate_layout()
    write_pass1(layout, pass1.labels, pass1.label_sections, pass1.symbols, sys.argv[2])
    print(f"Проход 1: text_size={layout['text_size']}, data_size={layout['data_size']}")