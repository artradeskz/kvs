#!/usr/bin/env python3
import subprocess
import sys
import os
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent.absolute()
PROJECT_ROOT = SCRIPT_DIR.parent.parent
SOURCE_REL = SCRIPT_DIR / "тест_адресации_р8.квс"

def clean():
    files = [
        "тест_адресации_р8.elf",
        "тест_адресации_р8.csv", 
        "тест_адресации_р8.аст",
        "тест_адресации_р8.токены",
        "тест_адресации_р8.константа",
        "тест_адресации_р8_pass4.log"
    ]
    for f in files:
        f_path = SCRIPT_DIR / f
        if f_path.exists():
            f_path.unlink()

def build():
    os.chdir(PROJECT_ROOT)
    build = subprocess.run(["python3", "kvs_build.py", str(SOURCE_REL)], 
                          capture_output=True, text=True)
    if build.returncode != 0:
        print(f"❌ Ошибка сборки: {build.returncode}", file=sys.stderr)
        print(build.stderr, file=sys.stderr)
        return False
    return True

def test_with_char(char, expected_code):
    """Проверка с конкретным символом"""
    print(f"DEBUG: Тест с символом '{char}' (ожидается код {expected_code})", file=sys.stderr)
    os.chdir(SCRIPT_DIR)
    
    elf_path = SCRIPT_DIR / "тест_адресации_р8.elf"
    if not elf_path.exists():
        print("❌ ELF файл не найден", file=sys.stderr)
        return False
    
    run = subprocess.run([str(elf_path), char], capture_output=True, text=True)
    
    # Проверяем код возврата (должен быть ASCII код символа)
    if run.returncode != expected_code:
        print(f"❌ Код возврата: ожидался {expected_code}, получен {run.returncode}", file=sys.stderr)
        return False
    
    print(f"DEBUG: Тест с символом '{char}' пройден", file=sys.stderr)
    return True

def main():
    print("DEBUG: Начало теста тест_адресации_р8", file=sys.stderr)
    
    if not build():
        clean()
        sys.exit(1)
    
    # Тестируем разные символы
    tests = [
        ('A', 65),
        ('B', 66),
        ('0', 48),
        ('z', 122),
        ('!', 33),
    ]
    
    all_passed = True
    for char, expected_code in tests:
        if not test_with_char(char, expected_code):
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