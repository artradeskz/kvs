#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Второй проход КВС
Генерирует машинный код и создаёт CSV-файл
"""

import sys
import struct
sys.path.insert(0, '.')
from kvs_data import PAGE_SIZE, align_up
from kvs_pass2_encoder import encode_instruction, parse_operand


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
    """Читает AST из файла"""
    ast_lines = []
    with open(input_file, 'r', encoding='utf-8') as f:
        for line in f:
            ast_lines.append(line.strip())
    return ast_lines


def read_pass1(input_file):
    """
    Читает результаты первого прохода:
    - PARAM: параметры компоновки (размеры, адреса)
    - LABEL: метки и их позиции
    - SYMBOL: константы
    """
    data = {}
    labels = {}
    label_sections = {}
    symbols = {}
    
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
                sec = parts[2]
                pos = int(parts[3])
                labels[label] = pos
                label_sections[label] = sec
            elif parts[0] == "SYMBOL":
                name = parts[1]
                value = int(parts[2])
                symbols[name] = value
    
    return data, labels, label_sections, symbols


# ========== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ПАРСИНГА AST ==========

def parse_ast_line(line):
    """
    Универсальный разбор строки AST.
    Возвращает (тип, словарь_полей).
    
    Форматы AST:
    - DIRECTIVE:имя
    - DIRECTIVE:имя:секция
    - DIRECTIVE:имя:секция:данные
    - DIRECTIVE:имя:имя_константы:значение
    - LABEL:имя:секция
    - INSTR:мнемоника:секция:операнд1,операнд2,...
    
    Операнды могут содержать двоеточия (MEM:reg_indirect:рбикс).
    Поэтому для INSTR используется специальный разбор: первые 3 двоеточия
    отделяют служебные поля, остальное — операнды.
    """
    if not line:
        return None, {}
    
    line_type = line.split(':')[0]
    
    if line_type == "INSTR":
        # Формат: INSTR:мнемоника:секция:операнды
        # Находим первые три двоеточия
        first_colon = line.find(':')
        second_colon = line.find(':', first_colon + 1)
        third_colon = line.find(':', second_colon + 1)
        
        if first_colon == -1 or second_colon == -1 or third_colon == -1:
            return "INSTR", {}
        
        mnemonic = line[first_colon + 1 : second_colon]
        section = line[second_colon + 1 : third_colon]
        operands_str = line[third_colon + 1 :]
        
        operands = []
        if operands_str:
            operands = operands_str.split(',')
        
        return "INSTR", {
            'mnemonic': mnemonic,
            'section': section,
            'operands': operands,
            'operands_str': operands_str
        }
    
    elif line_type == "DIRECTIVE":
        parts = line.split(':')
        directive = parts[1] if len(parts) > 1 else ""
        
        if directive in ('.текст', '.данные', '.бнд'):
            return "DIRECTIVE", {'directive': directive}
        
        elif directive == '.глобал':
            label = parts[2] if len(parts) > 2 else ""
            return "DIRECTIVE", {'directive': directive, 'label': label}
        
        elif directive in ('.строка_нуль', '.строка'):
            sec = parts[2] if len(parts) > 2 else ""
            s = parts[3] if len(parts) > 3 else ""
            return "DIRECTIVE", {'directive': directive, 'section': sec, 'string': s}
        
        elif directive == '.константа':
            name = parts[2] if len(parts) > 2 else ""
            value = parts[3] if len(parts) > 3 else ""
            return "DIRECTIVE", {'directive': directive, 'name': name, 'value': value}
        
        elif directive == '.байт':
            sec = parts[2] if len(parts) > 2 else ""
            bytes_str = parts[3] if len(parts) > 3 else ""
            return "DIRECTIVE", {'directive': directive, 'section': sec, 'bytes': bytes_str}
        
        elif directive in ('.резб', '.резс', '.рездс', '.резкс'):
            sec = parts[2] if len(parts) > 2 else ""
            count = parts[3] if len(parts) > 3 else "0"
            return "DIRECTIVE", {'directive': directive, 'section': sec, 'count': count}
        
        else:
            return "DIRECTIVE", {'directive': directive}
    
    elif line_type == "LABEL":
        parts = line.split(':')
        label_name = parts[1] if len(parts) > 1 else ""
        sec = parts[2] if len(parts) > 2 else ""
        return "LABEL", {'name': label_name, 'section': sec}
    
    return line_type, {}


# ========== ОСНОВНОЙ КЛАСС ВТОРОГО ПРОХОДА ==========

class Pass2:
    def __init__(self, pass1_data, labels, label_sections, symbols):
        self.labels = labels
        self.label_sections = label_sections
        self.symbols = symbols
        self.vaddr_text = pass1_data["vaddr_text"]
        text_size = pass1_data["text_size"]
        self.vaddr_data = align_up(self.vaddr_text + text_size, PAGE_SIZE)
        self.position = {".text": 0, ".data": 0}
        self.current_section = ".text"
        self.csv_lines = []
        self.data_bytes = {".text": bytearray(), ".data": bytearray()}
        
    def get_target_addr(self, mnemonic, operands):
        """Вычисляет целевой адрес для инструкций перехода"""
        jump_instructions = {
            "переход", "короткий_переход", "вызвать", "цикл",
            "переход_если_равно", "переход_если_неравно", "переход_если_меньше",
            "переход_если_больше", "переход_если_меньше_или_равно", "переход_если_больше_или_равно",
            "переход_если_перенос", "переход_если_нет_переноса", "переход_если_ноль", "переход_если_не_ноль",
            "короткий_переход_если_равно", "короткий_переход_если_неравно", "короткий_переход_если_меньше",
            "короткий_переход_если_больше", "короткий_переход_если_меньше_или_равно", "короткий_переход_если_больше_или_равно",
            "короткий_переход_если_перенос", "короткий_переход_если_нет_переноса",
            "короткий_переход_если_ноль", "короткий_переход_если_не_ноль"
        }
        
        try:
            if mnemonic in jump_instructions:
                target = parse_operand(operands[0], self.labels, self.label_sections, 
                                      self.symbols, self.vaddr_text, self.vaddr_data)
                return hex(target)
            elif mnemonic == "переместить_имм" and len(operands) >= 2:
                op_str = operands[1]
                if op_str in self.labels:
                    sec = self.label_sections[op_str]
                    addr = self.labels[op_str] + (self.vaddr_text if sec == ".text" else self.vaddr_data)
                    return hex(addr)
                elif op_str in self.symbols:
                    return hex(self.symbols[op_str])
        except Exception:
            return "ошибка"
        
        return ""
    
    def process_line(self, line):
        """Обрабатывает одну строку AST"""
        line_type, fields = parse_ast_line(line)
        
        if line_type == "DIRECTIVE":
            directive = fields.get('directive', '')
            
            if directive == '.текст':
                self.current_section = ".text"
            elif directive == '.данные':
                self.current_section = ".data"
            elif directive in ('.строка_нуль', '.строка'):
                s = fields.get('string', '')
                real_s = unescape_string(s)
                bstring = real_s.encode('utf-8')
                if directive == '.строка_нуль':
                    bstring += b'\x00'
                
                original_cmd = f'{directive} "{s}"'
                start_addr = self.vaddr_data + self.position[".data"]
                
                for i, byte in enumerate(bstring):
                    addr = start_addr + i
                    byte_hex = "{:02X}".format(byte)
                    cmd = original_cmd if i == 0 else ""
                    self.csv_lines.append((hex(addr), byte_hex, "", cmd))
                
                self.data_bytes[".data"] += bstring
                self.position[".data"] += len(bstring)
                
            elif directive == '.байт':
                bytes_str = fields.get('bytes', '')
                if bytes_str:
                    byte_values = bytes_str.split(',')
                    original_cmd = f".байт {bytes_str}"
                    start_addr = self.vaddr_data + self.position[".data"]
                    
                    for i, byte_str in enumerate(byte_values):
                        if byte_str.startswith('0x'):
                            val = int(byte_str, 16)
                        elif byte_str.isdigit() or (byte_str.startswith('-') and byte_str[1:].isdigit()):
                            val = int(byte_str)
                        else:
                            continue
                        
                        addr = start_addr + i
                        byte_hex = "{:02X}".format(val & 0xFF)
                        cmd = original_cmd if i == 0 else ""
                        self.csv_lines.append((hex(addr), byte_hex, "", cmd))
                        self.data_bytes[".data"].append(val & 0xFF)
                    
                    self.position[".data"] += len(byte_values)
                    
        elif line_type == "LABEL":
            label_name = fields.get('name', '')
            sec = fields.get('section', '')
            if label_name in self.labels:
                self.position[sec] = self.labels[label_name]
            
        elif line_type == "INSTR":
            mnemonic = fields.get('mnemonic', '')
            sec = fields.get('section', '')
            operands = fields.get('operands', [])
            
            if operands:
                original_cmd = f"{mnemonic} {', '.join(operands)}"
            else:
                original_cmd = mnemonic
            
            current_pos = self.position[sec]
            code = encode_instruction(mnemonic, operands, self.labels, self.label_sections,
                                     self.symbols, self.vaddr_text, self.vaddr_data, current_pos)
            
            target_addr = self.get_target_addr(mnemonic, operands)
            
            start_addr = (self.vaddr_text if sec == ".text" else self.vaddr_data) + current_pos
            
            for i, byte in enumerate(code):
                addr = start_addr + i
                byte_hex = "{:02X}".format(byte)
                cmd = original_cmd if i == 0 else ""
                addr_target = target_addr if i == 0 else ""
                self.csv_lines.append((hex(addr), byte_hex, addr_target, cmd))
            
            self.data_bytes[sec] += code
            self.position[sec] += len(code)
    
    def process_all(self, ast_lines):
        """Обрабатывает все строки AST"""
        for line in ast_lines:
            self.process_line(line)
        return self.csv_lines


def write_csv(csv_lines, output_file):
    """Записывает сгенерированные байты в CSV файл"""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("адрес;байт;целевой_адрес;исходная_команда\n")
        for addr, byte, target, cmd in csv_lines:
            if cmd and (';' in cmd or '\n' in cmd):
                cmd = '"' + cmd.replace('"', '""') + '"'
            f.write(f"{addr};{byte};{target};{cmd}\n")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Использование: python kvs_pass2.py <вход.аст> <вход.проход1> <выход.csv>")
        sys.exit(1)
    
    ast_lines = read_ast(sys.argv[1])
    pass1_data, labels, label_sections, symbols = read_pass1(sys.argv[2])
    
    pass2 = Pass2(pass1_data, labels, label_sections, symbols)
    csv_lines = pass2.process_all(ast_lines)
    write_csv(csv_lines, sys.argv[3])
    
    print(f"Проход 2: {len(csv_lines)} строк CSV записано в {sys.argv[3]}")
    print(f"  .text: {pass2.position['.text']} байт, виртуальный адрес: 0x{pass2.vaddr_text:x}")
    print(f"  .data: {pass2.position['.data']} байт, виртуальный адрес: 0x{pass2.vaddr_data:x}")