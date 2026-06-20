#!/usr/bin/env python3
import subprocess
import sys
import os
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent.absolute()
PROJECT_ROOT = SCRIPT_DIR.parent.parent
SOURCE_REL = SCRIPT_DIR / "тест_адресации2.квс"

def clean():
    files = [
        "тест_адресации2.elf",
        "тест_адресации2.csv", 
        "тест_адресации2.аст",
        "тест_адресации2.токены",
        "тест_адресации2.константа",
        "тест_адресации2_pass4.log"
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

def test_label_addressing():
    """Проверка абсолютной адресации по метке"""
    print("DEBUG: Тест абсолютной адресации по метке [переменная]", file=sys.stderr)
    os.chdir(SCRIPT_DIR)
    
    elf_path = SCRIPT_DIR / "тест_адресации2.elf"
    if not elf_path.exists():
        print("❌ ELF файл не найден", file=sys.stderr)
        return False
    
    run = subprocess.run([str(elf_path)], capture_output=True, text=True)
    
    # Ожидаемый код возврата = 43
    expected_code = 43
    
    if run.returncode != expected_code:
        print(f"❌ Код возврата: ожидался {expected_code}, получен {run.returncode}", file=sys.stderr)
        return False
    
    print("DEBUG: Тест абсолютной адресации по метке пройден", file=sys.stderr)
    return True

def main():
    print("DEBUG: Начало теста тест_адресации2", file=sys.stderr)
    
    if not build():
        clean()
        sys.exit(1)
    
    if test_label_addressing():
        clean()
        print("✅", file=sys.stderr)
        sys.exit(0)
    else:
        clean()
        print("❌", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()