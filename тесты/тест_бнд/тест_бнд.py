#!/usr/bin/env python3
import subprocess
import sys
import os
import re
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent.absolute()
PROJECT_ROOT = SCRIPT_DIR.parent.parent
SOURCE_REL = SCRIPT_DIR / "тест_бнд.квс"

def clean():
    files = [
        "тест_бнд.elf",
        "тест_бнд.csv", 
        "тест_бнд.аст",
        "тест_бнд.токены",
        "тест_бнд.константа",
        "тест_бнд_pass4.log"
    ]
    for f in files:
        f_path = SCRIPT_DIR / f
        if f_path.exists():
            f_path.unlink()

def build():
    os.chdir(PROJECT_ROOT)
    build = subprocess.run(["python3", "квс_сборка.py", str(SOURCE_REL)], 
                          capture_output=True, text=True)
    if build.returncode != 0:
        print(f"❌ Ошибка сборки: {build.returncode}", file=sys.stderr)
        print(build.stderr, file=sys.stderr)
        return False
    return True

def test_file_size():
    """Проверка: файл должен быть маленьким (BSS не в файле)"""
    print("DEBUG: Проверка размера файла", file=sys.stderr)
    elf_path = SCRIPT_DIR / "тест_бнд.elf"
    size = elf_path.stat().st_size
    
    max_size = 100 * 1024  # 100 КБ
    if size >= max_size:
        print(f"❌ Размер файла {size} байт (ожидалось < {max_size})", file=sys.stderr)
        return False
    
    print(f"DEBUG: Размер файла {size} байт (OK)", file=sys.stderr)
    return True

def test_bss_section():
    """Проверка секции .bss через readelf -S"""
    print("DEBUG: Проверка секции .bss", file=sys.stderr)
    os.chdir(SCRIPT_DIR)
    
    result = subprocess.run(["readelf", "-S", "тест_бнд.elf"], 
                          capture_output=True, text=True)
    
    lines = result.stdout.split('\n')
    expected_size = 1048576  # 1 МБ = 0x100000
    
    for i, line in enumerate(lines):
        if '.bss' in line and 'NOBITS' in line:
            if i + 1 < len(lines):
                size_line = lines[i + 1].strip()
                match = re.search(r'^([0-9a-fA-F]+)', size_line)
                if match:
                    size = int(match.group(1), 16)
                    if size == expected_size:
                        print(f"DEBUG: Размер .bss = {size} (OK)", file=sys.stderr)
                        return True
                    else:
                        print(f"❌ Размер .bss = {size} (ожидался {expected_size})", file=sys.stderr)
                        return False
    
    print("❌ Секция .bss не найдена или имеет неверный формат", file=sys.stderr)
    return False

def test_load_segment():
    """Проверка сегмента LOAD с BSS"""
    print("DEBUG: Проверка сегмента LOAD", file=sys.stderr)
    os.chdir(SCRIPT_DIR)
    
    result = subprocess.run(["readelf", "-l", "тест_бнд.elf"], 
                          capture_output=True, text=True)
    
    print("DEBUG: Вывод readelf -l:", file=sys.stderr)
    print(result.stdout, file=sys.stderr)
    
    lines = result.stdout.split('\n')
    expected_min = 1048576
    
    # Поиск LOAD сегмента с RW
    for i, line in enumerate(lines):
        print(f"DEBUG: Строка {i}: {repr(line)}", file=sys.stderr)
        if 'LOAD' in line and 'RW' in line:
            print(f"DEBUG: Найден LOAD RW на строке {i}: {line}", file=sys.stderr)
            # Ищем в следующих строках p_memsz
            for j in range(i + 1, min(i + 5, len(lines))):
                print(f"DEBUG:   Строка {j}: {repr(lines[j])}", file=sys.stderr)
                # Формат: 0x0000000000000001 0x0000000000101000 RW 0x1000
                matches = re.findall(r'0x([0-9a-fA-F]+)', lines[j])
                print(f"DEBUG:     Найдено hex: {matches}", file=sys.stderr)
                if len(matches) >= 2:
                    filesz = int(matches[0], 16)
                    memsz = int(matches[1], 16)
                    print(f"DEBUG:     p_filesz = {filesz}, p_memsz = {memsz}", file=sys.stderr)
                    if memsz >= expected_min:
                        print(f"DEBUG: p_memsz = {memsz} (OK)", file=sys.stderr)
                        return True
                    else:
                        print(f"❌ p_memsz = {memsz} (ожидалось >= {expected_min})", file=sys.stderr)
                        return False
            break
    else:
        # Альтернативный поиск: ищем по соответствию с .bss
        print("DEBUG: LOAD RW не найден, ищем по соответствию с .bss", file=sys.stderr)
        in_mapping = False
        for i, line in enumerate(lines):
            if 'Соответствие раздел-сегмент' in line:
                in_mapping = True
                print(f"DEBUG: Найдено 'Соответствие раздел-сегмент' на строке {i}", file=sys.stderr)
                continue
            if in_mapping and '.bss' in line:
                print(f"DEBUG: Найдена строка с .bss: {line}", file=sys.stderr)
                # Находим номер сегмента
                seg_match = re.search(r'(\d+)', line)
                if seg_match:
                    seg_num = int(seg_match.group(1))
                    print(f"DEBUG: Сегмент {seg_num} содержит .bss", file=sys.stderr)
                    # Теперь ищем этот сегмент в заголовках
                    for k, l in enumerate(lines):
                        if f'LOAD' in l and k < i:
                            print(f"DEBUG: Найден LOAD на строке {k}: {l}", file=sys.stderr)
                            # Проверяем его размер
                            for m in range(k + 1, min(k + 5, len(lines))):
                                matches = re.findall(r'0x([0-9a-fA-F]+)', lines[m])
                                if len(matches) >= 2:
                                    memsz = int(matches[1], 16)
                                    if memsz >= expected_min:
                                        print(f"DEBUG: p_memsz = {memsz} (OK)", file=sys.stderr)
                                        return True
                    break
    
    print("❌ Не найден LOAD сегмент с BSS", file=sys.stderr)
    return False

def test_execution():
    """Проверка: программа должна выполниться и вернуть 0"""
    print("DEBUG: Проверка выполнения", file=sys.stderr)
    os.chdir(SCRIPT_DIR)
    
    elf_path = SCRIPT_DIR / "тест_бнд.elf"
    run = subprocess.run([str(elf_path)], capture_output=True, text=True)
    
    if run.returncode != 0:
        print(f"❌ Код возврата {run.returncode} (ожидался 0)", file=sys.stderr)
        return False
    
    print("DEBUG: Выполнение успешно", file=sys.stderr)
    return True

def main():
    print("DEBUG: Начало теста тест_бнд", file=sys.stderr)
    
    if not build():
        clean()
        sys.exit(1)
    
    tests = [
        ("Размер файла", test_file_size),
        ("Секция .bss", test_bss_section),
        ("Сегмент LOAD", test_load_segment),
        ("Выполнение", test_execution),
    ]
    
    all_passed = True
    for name, test_func in tests:
        if not test_func():
            print(f"❌ Провалена проверка: {name}", file=sys.stderr)
            all_passed = False
            break
    
    clean()
    
    if all_passed:
        print("✅", file=sys.stderr)
        sys.exit(0)
    else:
        print("❌", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()