#!/usr/bin/env python3
import subprocess
import sys
import os
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent.absolute()
PROJECT_ROOT = SCRIPT_DIR.parent.parent
SOURCE_REL = SCRIPT_DIR / "тест_бнд_3.квс"

def clean():
    files = [
        "тест_бнд_3.elf",
        "тест_бнд_3.csv",
        "тест_бнд_3.аст",
        "тест_бнд_3.токены",
        "тест_бнд_3.константа",
        "тест_бнд_3_pass4.log"
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

def test_bss_mixed_addressing():
    """Проверка смешанной адресации в BSS:
       - абсолютная запись в абс_перем (0x41)
       - косвенная запись в косв_перем (0x11)
       - косвенное чтение из абс_перем (должно вернуть 0x41)
    """
    print("DEBUG: Тест BSS смешанной адресации (абсолютная + косвенная)", file=sys.stderr)
    os.chdir(SCRIPT_DIR)
    
    elf_path = SCRIPT_DIR / "тест_бнд_3.elf"
    if not elf_path.exists():
        print("❌ ELF файл не найден", file=sys.stderr)
        return False
    
    run = subprocess.run([str(elf_path)], capture_output=True, text=True)
    
    # Ожидаемый код возврата = 0x41 = 65
    expected_code = 65
    
    if run.returncode != expected_code:
        print(f"❌ Код возврата: ожидался {expected_code} (0x41), получен {run.returncode}", file=sys.stderr)
        return False
    
    print("DEBUG: BSS смешанная адресация работает: прочитано 0x41 из абс_перем через косвенную адресацию", file=sys.stderr)
    return True

def main():
    print("DEBUG: Начало теста тест_бнд_3 (BSS mixed addressing)", file=sys.stderr)
    
    if not build():
        clean()
        sys.exit(1)
    
    if test_bss_mixed_addressing():
        clean()
        print("✅", file=sys.stderr)
        sys.exit(0)
    else:
        clean()
        print("❌", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()