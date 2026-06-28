#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Тест для проверки операции деления и получения остатка
Запускает скомпилированную программу и проверяет код возврата
Ожидаемый результат: 42 % 10 = 2
"""

import subprocess
import sys
import os
from pathlib import Path

# Определяем пути
SCRIPT_DIR = Path(__file__).parent.absolute()
PROJECT_ROOT = SCRIPT_DIR.parent.parent
SOURCE_REL = SCRIPT_DIR / "остаток_от_деления.квс"

def clean():
    """Очищает артефакты сборки"""
    files = [
        "остаток_от_деления.elf",
        "остаток_от_деления.csv", 
        "остаток_от_деления.аст",
        "остаток_от_деления.токены",
        "остаток_от_деления.константа",
        "остаток_от_деления_pass4.log"
    ]
    for f in files:
        f_path = SCRIPT_DIR / f
        if f_path.exists():
            f_path.unlink()
            print(f"DEBUG: Удалён {f}", file=sys.stderr)

def build() -> bool:
    """
    Собирает тестовую программу с помощью КВС
    
    Returns:
        bool: True если сборка успешна, иначе False
    """
    print(f"DEBUG: Сборка {SOURCE_REL}", file=sys.stderr)
    os.chdir(PROJECT_ROOT)
    
    build = subprocess.run(
        ["python3", "квс_сборка.py", str(SOURCE_REL)], 
        capture_output=True, 
        text=True
    )
    
    if build.returncode != 0:
        print(f"❌ Ошибка сборки: {build.returncode}", file=sys.stderr)
        print(build.stderr, file=sys.stderr)
        return False
    
    print("DEBUG: Сборка успешна", file=sys.stderr)
    return True

def test_division_remainder() -> bool:
    """
    Запускает скомпилированную программу и проверяет код возврата
    42 % 10 = 2
    
    Returns:
        bool: True если код возврата = 2, иначе False
    """
    print("DEBUG: Запуск ELF, ожидается код возврата 2", file=sys.stderr)
    os.chdir(SCRIPT_DIR)
    
    elf_path = SCRIPT_DIR / "остаток_от_деления.elf"
    if not elf_path.exists():
        print("❌ ELF файл не найден", file=sys.stderr)
        return False
    
    # Запускаем программу без аргументов
    run = subprocess.run(
        [str(elf_path)], 
        capture_output=True, 
        text=True
    )
    
    expected_code = 2  # 42 % 10 = 2
    
    if run.returncode != expected_code:
        print(f"❌ Код возврата: ожидался {expected_code}, получен {run.returncode}", file=sys.stderr)
        if run.stderr:
            print(f"   stderr: {run.stderr}", file=sys.stderr)
        if run.stdout:
            print(f"   stdout: {run.stdout}", file=sys.stderr)
        return False
    
    print(f"DEBUG: Тест пройден (код {run.returncode})", file=sys.stderr)
    return True

def main():
    """Главная функция теста"""
    print("DEBUG: Начало теста остаток_от_деления", file=sys.stderr)
    
    # Собираем программу
    if not build():
        clean()
        sys.exit(1)
    
    # Запускаем тест
    if not test_division_remainder():
        clean()
        sys.exit(1)
    
    # Очищаем артефакты
    clean()
    
    print("✅ Все тесты пройдены!", file=sys.stderr)
    sys.exit(0)

if __name__ == "__main__":
    main()