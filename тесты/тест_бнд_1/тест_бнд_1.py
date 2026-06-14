#!/usr/bin/env python3
import subprocess
import sys
import os
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent.absolute()
PROJECT_ROOT = SCRIPT_DIR.parent.parent
SOURCE_REL = SCRIPT_DIR / "тест_бнд_1.квс"

def clean():
    files = [
        "тест_бнд_1.elf",
        "тест_бнд_1.csv",
        "тест_бнд_1.аст",
        "тест_бнд_1.токены",
        "тест_бнд_1.константа",
        "тест_бнд_1_pass4.log"
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

def test_bss_absolute_addressing():
    """Проверка абсолютной адресации в BSS: запись → очистка → чтение"""
    print("DEBUG: Тест BSS абсолютной адресации (запись/чтение)", file=sys.stderr)
    os.chdir(SCRIPT_DIR)
    
    elf_path = SCRIPT_DIR / "тест_бнд_1.elf"
    if not elf_path.exists():
        print("❌ ELF файл не найден", file=sys.stderr)
        return False
    
    run = subprocess.run([str(elf_path)], capture_output=True, text=True)
    
    # Ожидаемый код возврата = 0x42 = 66
    expected_code = 66
    
    if run.returncode != expected_code:
        print(f"❌ Код возврата: ожидался {expected_code} (0x42), получен {run.returncode}", file=sys.stderr)
        return False
    
    print("DEBUG: BSS абсолютная адресация работает: записано и прочитано 0x42", file=sys.stderr)
    return True

def main():
    print("DEBUG: Начало теста тест_бнд_1 (BSS absolute addressing)", file=sys.stderr)
    
    if not build():
        clean()
        sys.exit(1)
    
    if test_bss_absolute_addressing():
        clean()
        print("✅", file=sys.stderr)
        sys.exit(0)
    else:
        clean()
        print("❌", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()