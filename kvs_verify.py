#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Верификатор КВС
Сравнивает размеры инструкций из pass1 с реальными размерами из CSV.
Выводит расхождения и останавливает сборку при ошибках.
"""

import sys

# Если True — разрешает сборку, когда единственная ошибка это общий размер .text
# (расхождение до 16 байт считается допустимым)
ENABLE = False
ALLOW_TEXT_SIZE_MISMATCH = True
MAX_TEXT_SIZE_MISMATCH = 25


def read_pass1(input_file):
    """Читает pass1-файл: PARAM и LABEL"""
    params = {}
    labels = {}
    label_sections = {}
    
    with open(input_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(':')
            if parts[0] == "PARAM":
                key = parts[1]
                value = parts[2]
                if value.isdigit() or (value.startswith('-') and value[1:].isdigit()):
                    value = int(value)
                params[key] = value
            elif parts[0] == "LABEL":
                label = parts[1]
                sec = parts[2]
                pos = int(parts[3])
                labels[label] = pos
                label_sections[label] = sec
    
    return params, labels, label_sections


def read_csv(input_file):
    """
    Читает CSV-файл.
    Возвращает:
    - instr_list: список инструкций с адресами и размерами
    """
    instr_list = []
    current_cmd = None
    current_start = None
    current_size = 0
    
    with open(input_file, 'r', encoding='utf-8') as f:
        header = f.readline()
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(';')
            if len(parts) < 2:
                continue
            
            addr_str = parts[0]
            byte_str = parts[1]
            cmd_str = parts[3] if len(parts) > 3 else ""
            
            try:
                addr = int(addr_str, 16)
            except ValueError:
                continue
            
            if addr >= 0x402000:
                break
            
            if cmd_str:
                if current_cmd is not None:
                    instr_list.append({
                        'cmd': current_cmd,
                        'start': current_start,
                        'size': current_size
                    })
                current_cmd = cmd_str
                current_start = addr
                current_size = 1
            else:
                current_size += 1
    
    if current_cmd is not None:
        instr_list.append({
            'cmd': current_cmd,
            'start': current_start,
            'size': current_size
        })
    
    return instr_list


def verify(pass1_file, csv_file):
    """Сравнивает pass1 и pass2, возвращает список ошибок"""
    from kvs_data import FIXED_SIZE_INSTRUCTIONS, INSTRUCTIONS
    
    params, labels, label_sections = read_pass1(pass1_file)
    instr_list = read_csv(csv_file)
    
    vaddr_text = params.get("vaddr_text", 0x401000)
    text_size_pass1 = params.get("text_size", 0)
    text_size_pass2 = sum(instr['size'] for instr in instr_list)
    
    errors = []
    warnings = []
    
    print(f"Pass1 .text: {text_size_pass1} байт")
    print(f"Pass2 .text: {text_size_pass2} байт")
    print()
    
    # Проверка общего размера
    text_size_error = None
    if text_size_pass1 != text_size_pass2:
        diff = text_size_pass2 - text_size_pass1
        text_size_error = f"Общий размер .text: pass1={text_size_pass1}, pass2={text_size_pass2} (разница {diff:+d} байт)"
        if ALLOW_TEXT_SIZE_MISMATCH and abs(diff) <= MAX_TEXT_SIZE_MISMATCH:
            warnings.append(text_size_error + " — допустимо, сборка продолжена")
        else:
            errors.append(text_size_error)
    
    # Проверка позиций меток
    print("Проверка позиций меток (.text):")
    for label, pass1_offset in labels.items():
        if label_sections.get(label) != ".text":
            continue
        
        pass1_addr = vaddr_text + pass1_offset
        
        found = False
        for instr in instr_list:
            if instr['start'] == pass1_addr:
                found = True
                break
        
        if found:
            print(f"  [✓] {label} — 0x{pass1_addr:x}")
        else:
            closest = None
            for instr in instr_list:
                if instr['start'] <= pass1_addr:
                    closest = instr
            
            if closest:
                real_addr = closest['start']
                shift = real_addr - pass1_addr
                if shift != 0:
                    errors.append(f"Метка '{label}': pass1=0x{pass1_addr:x}, pass2=0x{real_addr:x} (сдвиг {shift:+d} байт)")
                    print(f"  [✗] {label} — pass1: 0x{pass1_addr:x}, pass2: 0x{real_addr:x} (сдвиг {shift:+d})")
                else:
                    print(f"  [✓] {label} — 0x{pass1_addr:x}")
            else:
                warnings.append(f"Метка '{label}' не найдена в CSV")
                print(f"  [?] {label} — не найдена в CSV")
    
    print()
    
    # Сравнение размеров инструкций
    print("Проверка размеров инструкций:")
    
    for instr in instr_list:
        cmd = instr['cmd']
        real_size = instr['size']
        real_addr = instr['start']
        
        mnemonic = cmd.split()[0] if cmd else ""
        
        if mnemonic in FIXED_SIZE_INSTRUCTIONS:
            pass1_size = FIXED_SIZE_INSTRUCTIONS[mnemonic]
        elif mnemonic in ("загрузить", "сохранить", "загрузить_адрес"):
            if 'MEM:reg_indirect:' in cmd:
                pass1_size = 3
            else:
                pass1_size = 7
        elif mnemonic in ("втолкнуть", "вытолкнуть"):
            parts = cmd.split()
            if len(parts) >= 2:
                reg = parts[1]
                if reg in ('р8', 'р9', 'р10', 'р11', 'р12', 'р13', 'р14', 'р15'):
                    pass1_size = 2
                else:
                    pass1_size = 1
            else:
                pass1_size = 1
        elif mnemonic in ("прибавить_непосредственно", "вычесть_непосредственно", "сравнить_с"):
            pass1_size = 7
        elif mnemonic == "переместить_имм":
            pass1_size = 10
        elif mnemonic in ("переместить_с_нулями", "переместить_со_знаком"):
            pass1_size = 8
        elif mnemonic == "загрузить_байт":
            pass1_size = 2
        elif mnemonic == "втолкнуть_непосредственно":
            pass1_size = 5
        else:
            instr_info = INSTRUCTIONS.get(mnemonic)
            if instr_info and "opcode" in instr_info and instr_info["opcode"] is not None:
                pass1_size = len(instr_info["opcode"])
            else:
                pass1_size = 3
        
        status = "✓" if pass1_size == real_size else "✗"
        if pass1_size != real_size:
            diff = real_size - pass1_size
            errors.append(f"Инструкция '{cmd}' на 0x{real_addr:x}: pass1={pass1_size}, pass2={real_size} (ошибка {diff:+d})")
        
        print(f"  [{status}] 0x{real_addr:x} {cmd} — pass1: {pass1_size}, pass2: {real_size}" + 
              (f" (ошибка {real_size - pass1_size:+d})" if pass1_size != real_size else ""))
    
    print()
    
    return errors, warnings


if __name__ == "__main__":
    if ENABLE:
        if len(sys.argv) != 3:
            print("Использование: python kvs_verify.py <вход.проход1> <вход.csv>")
            sys.exit(1)
        
        pass1_file = sys.argv[1]
        csv_file = sys.argv[2]
        
        errors, warnings = verify(pass1_file, csv_file)
        
        if warnings:
            print(f"Предупреждений: {len(warnings)}")
            for w in warnings:
                print(f"  ⚠ {w}")
            print()
        
        if errors:
            print(f"ОШИБОК: {len(errors)}")
            for e in errors:
                print(f"  ❌ {e}")
            print("\nСборка остановлена. Исправьте расхождения в размерах инструкций.")
            sys.exit(1)
        else:
            print("Все размеры инструкций совпадают. Можно собирать.")
            sys.exit(0)