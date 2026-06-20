#!/usr/bin/env python3
import subprocess
import sys
import os
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent.absolute()
PROJECT_ROOT = SCRIPT_DIR.parent.parent
SOURCE_REL = SCRIPT_DIR / "вывод_аргумента.квс"

def clean():
    files = [
        "вывод_аргумента.elf",
        "вывод_аргумента.csv", 
        "вывод_аргумента.аст",
        "вывод_аргумента.токены",
        "вывод_аргумента.константа",
        "вывод_аргумента_pass4.log"
    ]
    for f in files:
        f_path = SCRIPT_DIR / f
        if f_path.exists():
            f_path.unlink()

def build():
    os.chdir(PROJECT_ROOT)
    build = subprocess.run(["python3", "квс_сбоорка.py", str(SOURCE_REL)], 
                          capture_output=True, text=True)
    if build.returncode != 0:
        print(f"❌ Ошибка сборки: {build.returncode}", file=sys.stderr)
        print(build.stderr, file=sys.stderr)
        return False
    return True

def test_no_arg():
    """Сценарий 1: запуск без аргумента"""
    print("DEBUG: Тест без аргумента", file=sys.stderr)
    os.chdir(SCRIPT_DIR)
    
    elf_path = SCRIPT_DIR / "вывод_аргумента.elf"
    if not elf_path.exists():
        print("❌ ELF файл не найден", file=sys.stderr)
        return False
    
    run = subprocess.run([str(elf_path)], capture_output=True, text=True)
    
    # Ожидаемый вывод с нулевым байтом (как в сложном_тесте)
    expected_output = "Ошибка не передан аргумент\n\x00"
    
    if run.stdout != expected_output:
        print(f"❌ Без аргумента: вывод не совпадает", file=sys.stderr)
        print(f"   Ожидалось: {repr(expected_output)}", file=sys.stderr)
        print(f"   Получено:  {repr(run.stdout)}", file=sys.stderr)
        return False
    
    # Код возврата должен быть 1 (ошибка)
    if run.returncode != 1:
        print(f"❌ Без аргумента: код возврата {run.returncode} (ожидался 1)", file=sys.stderr)
        return False
    
    print("DEBUG: Тест без аргумента пройден", file=sys.stderr)
    return True

def test_with_arg():
    """Сценарий 2: запуск с аргументом"""
    print("DEBUG: Тест с аргументом", file=sys.stderr)
    os.chdir(SCRIPT_DIR)
    
    test_arg = "ccsfghdfngbf"
    elf_path = SCRIPT_DIR / "вывод_аргумента.elf"
    
    run = subprocess.run([str(elf_path), test_arg], capture_output=True, text=True)
    
    # Ожидаемый вывод = переданный аргумент (без \n и без \x00)
    expected_output = test_arg
    
    if run.stdout != expected_output:
        print(f"❌ С аргументом: вывод не совпадает", file=sys.stderr)
        print(f"   Аргумент: {test_arg}", file=sys.stderr)
        print(f"   Ожидалось: {repr(expected_output)}", file=sys.stderr)
        print(f"   Получено:  {repr(run.stdout)}", file=sys.stderr)
        return False
    
    # Код возврата должен быть 0
    if run.returncode != 0:
        print(f"❌ С аргументом: код возврата {run.returncode} (ожидался 0)", file=sys.stderr)
        return False
    
    print("DEBUG: Тест с аргументом пройден", file=sys.stderr)
    return True

def main():
    print("DEBUG: Начало теста вывод_аргумента", file=sys.stderr)
    
    if not build():
        clean()
        sys.exit(1)
    
    no_arg_ok = test_no_arg()
    with_arg_ok = test_with_arg()
    
    clean()
    
    if no_arg_ok and with_arg_ok:
        print("✅", file=sys.stderr)
        sys.exit(0)
    else:
        print("❌", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()