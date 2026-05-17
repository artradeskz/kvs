#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Первый проход КВС
Вычисляет размеры секций и адреса меток
"""

import sys
import re
sys.path.insert(0, '.')
from kvs_data import PAGE_SIZE, text_vaddr_base, data_vaddr_base, align_up, INSTRUCTIONS

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

def parse_memory_operand(operand_str):
    """
    Анализирует операнд памяти вида [reg + reg*scale + disp]
    Возвращает словарь с информацией:
    - has_base: bool
    - base_reg: str or None
    - has_index: bool
    - index_reg: str or None
    - scale: int (1,2,4,8)
    - has_disp: bool
    - disp_value: int (если есть)
    - disp_size: 1 или 4
    """
    if not operand_str.startswith('[') or not operand_str.endswith(']'):
        return None
    
    content = operand_str[1:-1].strip()
    if not content:
        return None
    
    result = {
        'has_base': False,
        'base_reg': None,
        'has_index': False,
        'index_reg': None,
        'scale': 1,
        'has_disp': False,
        'disp_value': 0,
        'disp_size': 0
    }
    
    # Проверяем, не является ли содержимое просто числом (абсолютный адрес)
    if content.isdigit() or (content.startswith('0x') and len(content) > 2 and content[2:].replace('0','').replace('1','').replace('2','').replace('3','').replace('4','').replace('5','').replace('6','').replace('7','').replace('8','').replace('9','').replace('a','').replace('b','').replace('c','').replace('d','').replace('e','').replace('f','').replace('A','').replace('B','').replace('C','').replace('D','').replace('E','').replace('F','') == ''):
        result['has_disp'] = True
        if content.startswith('0x'):
            result['disp_value'] = int(content, 16)
        else:
            result['disp_value'] = int(content)
        result['disp_size'] = 4
        return result
    
    # Простой регистр без смещения
    if content in ['раикс', 'рбикс', 'рсикс', 'рдикс', 'рсипи', 'рбипи', 'рсиай', 'рдиай',
                   'р8', 'р9', 'р10', 'р11', 'р12', 'р13', 'р14', 'р15']:
        result['has_base'] = True
        result['base_reg'] = content
        return result
    
    # Разбираем выражение: регистр [+- регистр[*масштаб] [+- смещение]]
    parts = re.split(r'([+\-])', content)
    
    for part in parts:
        part = part.strip()
        if not part or part in '+-':
            continue
        
        if part in ['раикс', 'рбикс', 'рсикс', 'рдикс', 'рсипи', 'рбипи', 'рсиай', 'рдиай',
                    'р8', 'р9', 'р10', 'р11', 'р12', 'р13', 'р14', 'р15']:
            if not result['has_base']:
                result['has_base'] = True
                result['base_reg'] = part
            elif not result['has_index']:
                result['has_index'] = True
                result['index_reg'] = part
        elif part.isdigit() or (part.startswith('0x') and len(part) > 2):
            result['has_disp'] = True
            if part.startswith('0x'):
                result['disp_value'] = int(part, 16)
            else:
                result['disp_value'] = int(part)
        elif '*' in part:
            reg_part, scale_part = part.split('*')
            reg_part = reg_part.strip()
            scale_part = scale_part.strip()
            if reg_part in ['раикс', 'рбикс', 'рсикс', 'рдикс', 'рсипи', 'рбипи', 'рсиай', 'рдиай',
                            'р8', 'р9', 'р10', 'р11', 'р12', 'р13', 'р14', 'р15']:
                result['has_index'] = True
                result['index_reg'] = reg_part
                result['scale'] = int(scale_part)
    
    if result['has_disp']:
        if -128 <= result['disp_value'] <= 127:
            result['disp_size'] = 1
        else:
            result['disp_size'] = 4
    
    return result

def estimate_memory_operand_size(operand_str):
    """Оценивает размер операнда памяти в байтах (ModR/M + SIB + disp)"""
    if not operand_str:
        return 0
    
    addr_mode = parse_memory_operand(operand_str)
    if addr_mode is None:
        return 0
    
    size = 1
    
    if addr_mode['has_index']:
        size += 1
    
    if addr_mode['has_disp']:
        size += addr_mode['disp_size']
    
    return size

class Pass1:
    def __init__(self):
        self.labels = {}
        self.label_sections = {}
        self.symbols = {}
        self.position = {".text": 0, ".data": 0, ".бнд": 0}
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
            elif directive == '.бнд':
                self.current_section = ".бнд"
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
                value_str = parts[3]
                if value_str.isdigit():
                    self.symbols[name] = int(value_str)
                elif value_str.startswith('0x'):
                    self.symbols[name] = int(value_str, 16)
                else:
                    self.symbols[name] = 0
            elif directive == '.байт':
                sec = parts[2]
                if len(parts) > 3 and parts[3]:
                    num_bytes = len(parts[3].split(','))
                    self.position[sec] += num_bytes

            # Директивы резервирования в .бнд
            elif directive == '.резб':
                count = int(parts[3])
                self.position['.бнд'] += count * 1

            elif directive == '.резс':
                count = int(parts[3])
                self.position['.бнд'] += count * 2

            elif directive == '.рездс':
                count = int(parts[3])
                self.position['.бнд'] += count * 4

            elif directive == '.резкс':
                count = int(parts[3])
                self.position['.бнд'] += count * 8
                    
        elif line_type == "LABEL":
            label_name = parts[1]
            sec = parts[2]
            self.labels[label_name] = self.position[sec]
            self.label_sections[label_name] = sec
            
        elif line_type == "INSTR":
            mnemonic = parts[1]
            sec = parts[2]
            operands_str = parts[3] if len(parts) > 3 else ""
            operands = operands_str.split(',') if operands_str else []
            size = self.estimate_size(mnemonic, operands)
            self.position[sec] += size
    
    def estimate_size(self, mnemonic, operands):
        """Динамический расчёт размера инструкции"""
        
        # Инструкции с памятью (загрузить, сохранить, загрузить_адрес)
        if mnemonic in ("загрузить", "сохранить", "загрузить_адрес"):
            # RIP-relative: REX (1) + opcode (1) + ModR/M (1) + disp32 (4) = 7
            return 7
        
        # Инструкции без операндов
        if mnemonic in ("вызов_системы", "нет_операции", "вернуться", "остановить", "отладка"):
            instr = INSTRUCTIONS.get(mnemonic)
            if instr and "opcode" in instr:
                return len(instr["opcode"])
            return 2
        
        # Таблица фиксированных размеров
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
            "и": 3,
            "или": 3,
            "исключающее_или": 3,
            "инвертировать": 3,
            "отрицать": 3,
            "втолкнуть": 2,
            "вытолкнуть": 2,
            "втолкнуть_непосредственно": 5,
            "умножить": 3,
            "умножить_знаковое": 3,
            "разделить": 3,
            "разделить_знаковое": 3,
            "сдвиг_влево": 4,
            "сдвиг_вправо": 4,
            "сдвиг_арифметический_вправо": 4,
            "вращать_влево": 4,
            "вращать_вправо": 4,
            "цикл": 2,
            "обменять": 4,
            "прервать": 2,
            "ввод_байта": 2,
            "вывод_байта": 2,
            "установить_перенос": 1,
            "сбросить_перенос": 1,
            "установить_направление": 1,
            "сбросить_направление": 1,
            "втолкнуть_флаги": 1,
            "вытолкнуть_флаги": 1,
            "переместить_байт": 1,
            "переместить_слово": 1,
            "сравнить_байты": 1,
            "сканировать_байт": 1,
            "идентифицировать_процессор": 2,
            "прочитать_счётчик": 2,
        }
        return size_map.get(mnemonic, 3)
    
    def calculate_layout(self):
        text_size = self.position[".text"]
        data_size = self.position[".data"]
        bnd_size = self.position[".бнд"]
        
        elf_header_size = 64
        ph_size = 56
        ph_num = 3
        ph_table_size = ph_num * ph_size
        
        offset_text = align_up(elf_header_size + ph_table_size, PAGE_SIZE)
        offset_data = align_up(offset_text + text_size, PAGE_SIZE)
        vaddr_text = text_vaddr_base
        vaddr_data = align_up(vaddr_text + text_size, PAGE_SIZE)
        vaddr_bnd = align_up(vaddr_data + data_size, PAGE_SIZE)
        
        comment_size = len("Сборщик КВС".encode('utf-8')) + 1
        offset_comment = align_up(offset_data + data_size, 1)
        
        # shstrtab теперь включает ".bss"
        if bnd_size > 0:
            shstrtab_content = b"\x00.text\x00.data\x00.bss\x00.comment\x00.shstrtab\x00"
        else:
            shstrtab_content = b"\x00.text\x00.data\x00.comment\x00.shstrtab\x00"
        shstrtab_size = len(shstrtab_content)
        shstrtab_offset = align_up(offset_comment + comment_size, 8)
        shdr_offset = align_up(shstrtab_offset + shstrtab_size, 16)
        
        return {
            "text_size": text_size,
            "data_size": data_size,
            "bnd_size": bnd_size,
            "offset_text": offset_text,
            "offset_data": offset_data,
            "vaddr_text": vaddr_text,
            "vaddr_data": vaddr_data,
            "vaddr_bnd": vaddr_bnd,
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
    print(f"Проход 1: text_size={layout['text_size']}, data_size={layout['data_size']}, bnd_size={layout['bnd_size']}")