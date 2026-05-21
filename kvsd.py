#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
kvsd.py
Дизассемблер ELF-файлов для КВС с кастомным синтаксисом
"""

import argparse
import os
import subprocess
import sys

from kvsd_data import translate_mnemonic, translate_operand

try:
    from elfreader import (
        read_elf_header, read_section_headers, get_section_name,
        SHT_PROGBITS, EM_X86_64
    )
except ImportError:
    print("Ошибка: не найден модуль elfreader.py", file=sys.stderr)
    sys.exit(1)


def parse_bytes_hex(bytes_str):
    """Преобразует строку шестнадцатеричных байтов в список байтов."""
    result = []
    for i in range(0, len(bytes_str), 2):
        byte_hex = bytes_str[i:i+2]
        if byte_hex:
            result.append(int(byte_hex, 16))
    return result


def extract_displacement(bytes_list, pos, size, little_endian=True):
    """Извлекает смещение из байтов."""
    if pos + size > len(bytes_list):
        return None
    if little_endian:
        result = 0
        for i in range(size):
            result |= bytes_list[pos + i] << (i * 8)
        return result
    else:
        result = 0
        for i in range(size):
            result = (result << 8) | bytes_list[pos + i]
        return result


def get_instruction_length(mnemonic, bytes_list):
    """Определяет длину инструкции в байтах."""
    fixed_lengths = {
        "вернуться": 1, "нет_операции": 1, "остановить": 1, "отладка": 1,
        "втолкнуть_флаги": 1, "вытолкнуть_флаги": 1,
        "установить_перенос": 1, "сбросить_перенос": 1,
        "установить_направление": 1, "сбросить_направление": 1,
        "переместить_байт": 1, "переместить_слово": 1,
        "сравнить_байты": 1, "сканировать_байт": 1,
        "вызов_системы": 2, "прервать": 2, "цикл": 2,
        "короткий_переход": 2, "короткий_переход_если_равно": 2,
        "короткий_переход_если_неравно": 2, "короткий_переход_если_меньше": 2,
        "короткий_переход_если_больше": 2, "ввод_байта": 2, "вывод_байта": 2,
        "переместить": 3, "сравнить": 3, "проверить": 3,
        "прибавить": 3, "вычесть": 3, "и": 3, "или": 3, "исключающее_или": 3,
        "увеличить": 3, "уменьшить": 3, "загрузить": 3, "сохранить": 3,
        "загрузить_адрес": 3, "обменять": 4,
        "сдвиг_влево": 4, "сдвиг_вправо": 4, "сдвиг_арифметический_вправо": 4,
        "вращать_влево": 4, "вращать_вправо": 4,
        "вращать_через_перенос_влево": 4, "вращать_через_перенос_вправо": 4,
        "переход": 5, "вызвать": 5, "переход_если_равно": 6,
        "переход_если_неравно": 6, "переход_если_ноль": 6,
        "переход_если_не_ноль": 6, "переход_если_меньше": 6,
        "переход_если_больше": 6,
    }
    
    if mnemonic in fixed_lengths:
        return fixed_lengths[mnemonic]
    
    if mnemonic == "переместить_имм":
        if len(bytes_list) >= 2:
            opcode = bytes_list[0] if bytes_list else 0
            if opcode == 0x48 and len(bytes_list) > 1 and bytes_list[1] >= 0xB8:
                return 10
            elif opcode >= 0xB8 and opcode <= 0xBF:
                return 5
        return 7
    
    if mnemonic in ["сравнить_с", "прибавить_непосредственно", "вычесть_непосредственно"]:
        return 7
    
    return len(bytes_list)


def compute_target_address(address, mnemonic, bytes_list):
    """Вычисляет целевой адрес для инструкций перехода."""
    relative_jumps = {
        "переход", "короткий_переход", "переход_если_равно", "переход_если_неравно",
        "переход_если_меньше", "переход_если_больше", "переход_если_ноль",
        "переход_если_не_ноль", "короткий_переход_если_равно", "короткий_переход_если_неравно",
        "короткий_переход_если_меньше", "короткий_переход_если_больше",
        "короткий_переход_если_перенос", "короткий_переход_если_нет_переноса",
        "вызвать", "цикл"
    }
    
    if mnemonic not in relative_jumps:
        return ""
    
    instr_len = get_instruction_length(mnemonic, bytes_list)
    
    if instr_len == 2 and len(bytes_list) >= 2:
        displacement = bytes_list[1]
        if displacement > 127:
            displacement = displacement - 256
        target = address + instr_len + displacement
        return f"0x{target:x}"
    
    elif instr_len == 5 and len(bytes_list) >= 5:
        displacement = extract_displacement(bytes_list, 1, 4)
        if displacement is not None:
            if displacement > 0x7FFFFFFF:
                displacement = displacement - 0x100000000
            target = address + instr_len + displacement
            return f"0x{target:x}"
    
    elif instr_len == 6 and len(bytes_list) >= 6:
        displacement = extract_displacement(bytes_list, 2, 4)
        if displacement is not None:
            if displacement > 0x7FFFFFFF:
                displacement = displacement - 0x100000000
            target = address + instr_len + displacement
            return f"0x{target:x}"
    
    return ""


def parse_ndisasm_line(line):
    """Разбирает строку вывода ndisasm и переводит её."""
    line = line.strip()
    if not line:
        return None
    
    parts = line.split(maxsplit=2)
    if len(parts) < 3:
        return None
    
    address_str = parts[0]
    bytes_hex = parts[1]
    rest = parts[2]
    
    # Разделяем мнемонику и операнды
    rest_parts = rest.split(maxsplit=1)
    mnemonic_orig = rest_parts[0]
    operands_orig = rest_parts[1] if len(rest_parts) > 1 else ""
    
    # Вычисляем длину инструкции
    bytes_list = parse_bytes_hex(bytes_hex)
    instr_len = len(bytes_list)
    
    # Переводим мнемонику (с учётом операндов и длины)
    translated_mnemonic = translate_mnemonic(mnemonic_orig, operands_orig, instr_len)
    # Переводим операнды (регистры внутри)
    translated_operands = translate_operand(operands_orig)
    
    return {
        'address': int(address_str, 16),
        'address_hex': address_str,
        'bytes_hex': bytes_hex,
        'mnemonic': translated_mnemonic,
        'operands': translated_operands,
        'instr_len': instr_len
    }


def filter_by_address_range(disasm_output, start_addr, end_addr):
    """
    Оставляет только строки, адрес которых входит в диапазон [start_addr, end_addr).
    """
    filtered_lines = []
    for line in disasm_output.splitlines():
        if not line.strip():
            continue
        addr_str = line.split(maxsplit=1)[0]
        try:
            addr = int(addr_str, 16)
            if start_addr <= addr < end_addr:
                filtered_lines.append(line)
        except ValueError:
            continue
    return '\n'.join(filtered_lines)


def generate_csv_table(disasm_output):
    """Генерирует CSV-таблицу из вывода ndisasm."""
    rows = []
    
    for line in disasm_output.splitlines():
        parsed = parse_ndisasm_line(line)
        if not parsed:
            continue
        
        address = parsed['address']
        bytes_hex = parsed['bytes_hex']
        mnemonic = parsed['mnemonic']
        operands = parsed['operands']
        
        # Формируем исходную команду
        if operands:
            original_cmd = f"{mnemonic} {operands}"
        else:
            original_cmd = mnemonic
        
        bytes_list = parse_bytes_hex(bytes_hex)
        target = compute_target_address(address, mnemonic, bytes_list)
        
        # Разбиваем байты на отдельные
        byte_parts = [bytes_hex[i:i+2] for i in range(0, len(bytes_hex), 2)]
        
        for i, byte in enumerate(byte_parts):
            byte_address = address + i
            if i == 0:
                rows.append({
                    'address': f"0x{byte_address:x}",
                    'bytes': byte,
                    'target': target,
                    'cmd': original_cmd
                })
            else:
                rows.append({
                    'address': f"0x{byte_address:x}",
                    'bytes': byte,
                    'target': "",
                    'cmd': ""
                })
    
    return rows


def disassemble_elf_to_csv(elf_file, output_file=None):
    """Дизассемблирует ELF-файл и сохраняет результат в CSV."""
    try:
        if not os.path.exists(elf_file):
            return False, f"Файл {elf_file} не найден"
        
        if not output_file:
            base_name = os.path.splitext(elf_file)[0]
            output_file = f"{base_name}.elf.csv"
        
        with open(elf_file, 'rb') as f:
            hdr = read_elf_header(f)
            if hdr['e_machine'] != EM_X86_64:
                print(f"Предупреждение: архитектура не x86-64")
            
            if hdr['e_shnum'] == 0:
                return False, "Файл не содержит таблицы секций"
            
            sections = read_section_headers(f, hdr['e_shoff'], hdr['e_shnum'])
            shstrtab = sections[hdr['e_shstrndx']]
            shstrtab_offset = shstrtab['sh_offset']
            shstrtab_size = shstrtab['sh_size']
            
            offset, size, vaddr = None, None, None
            for sec in sections:
                name = get_section_name(f, shstrtab_offset, shstrtab_size, sec['sh_name'])
                if name == '.text' and sec['sh_type'] == SHT_PROGBITS:
                    offset = sec['sh_offset']
                    size = sec['sh_size']
                    vaddr = sec['sh_addr']
                    break
            
            if offset is None:
                return False, "Секция .text не найдена"
            
            print(f"Секция .text: адрес 0x{vaddr:x}, размер 0x{size:x} ({size} байт)")
        
        cmd = ['ndisasm', '-b64', '-o', f'0x{vaddr - offset:x}', elf_file]
        print(f"Запуск: {' '.join(cmd)}")
        
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        if result.returncode != 0:
            return False, f"Ошибка ndisasm: {result.stderr.strip()}"
        
        end_addr = vaddr + size
        filtered_output = filter_by_address_range(result.stdout, vaddr, end_addr)
        
        if not filtered_output:
            print("Предупреждение: после фильтрации не осталось строк")
            rows = []
        else:
            rows = generate_csv_table(filtered_output)
        
        with open(output_file, 'w', encoding='utf-8') as out_f:
            out_f.write("адрес;байт;целевой_адрес;исходная_команда\n")
            for row in rows:
                out_f.write(f"{row['address']};{row['bytes']};{row['target']};{row['cmd']}\n")
        
        print(f"CSV сохранён: {output_file} (строк: {len(rows)})")
        return True, output_file
        
    except FileNotFoundError:
        return False, "ndisasm не найден. Установите NASM"
    except Exception as e:
        return False, str(e)


def main():
    parser = argparse.ArgumentParser(description='Дизассемблер ELF-файлов для КВС')
    parser.add_argument('input_file', help='Путь к ELF-файлу')
    parser.add_argument('-o', '--output', help='Выходной CSV-файл')
    args = parser.parse_args()
    
    print(f"Дизассемблирование: {args.input_file}")
    success, result = disassemble_elf_to_csv(args.input_file, args.output)
    
    if success:
        print(f"\nГотово! Результат: {result}")
    else:
        print(f"Ошибка: {result}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()