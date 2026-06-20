#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Тест для проверки косвенной адресации через регистр R9
Запускает скомпилированную программу с различными аргументами
и проверяет код возврата (должен быть равен ASCII коду первого символа)
"""

import subprocess
import sys
import os
from pathlib import Path

# Определяем пути
SCRIPT_DIR = Path(__file__).parent.absolute()
PROJECT_ROOT = SCRIPT_DIR.parent.parent
SOURCE_REL = SCRIPT_DIR / "тест_адресации_р9.квс"

def clean():
    """Очищает артефакты сборки"""
    files = [
        "тест_адресации_р9.elf",
        "тест_адресации_р9.csv", 
        "тест_адресации_р9.аст",
        "тест_адресации_р9.токены",
        "тест_адресации_р9.константа",
        "тест_адресации_р9_pass4.log"
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

def test_with_char(char: str, expected_code: int) -> bool:
    """
    Запускает скомпилированную программу с одним символом в качестве аргумента
    и проверяет код возврата
    
    Args:
        char: символ для передачи в программу
        expected_code: ожидаемый ASCII код символа
    
    Returns:
        bool: True если код возврата совпадает с ожидаемым, иначе False
    """
    print(f"DEBUG: Тест с символом '{char}' (ожидается код {expected_code})", file=sys.stderr)
    os.chdir(SCRIPT_DIR)
    
    elf_path = SCRIPT_DIR / "тест_адресации_р9.elf"
    if not elf_path.exists():
        print("❌ ELF файл не найден", file=sys.stderr)
        return False
    
    # Запускаем программу с аргументом
    run = subprocess.run(
        [str(elf_path), char], 
        capture_output=True, 
        text=True
    )
    
    # Проверяем код возврата (должен быть ASCII код символа)
    if run.returncode != expected_code:
        print(f"❌ Код возврата: ожидался {expected_code}, получен {run.returncode}", file=sys.stderr)
        if run.stderr:
            print(f"   stderr: {run.stderr}", file=sys.stderr)
        if run.stdout:
            print(f"   stdout: {run.stdout}", file=sys.stderr)
        return False
    
    print(f"DEBUG: Тест с символом '{char}' пройден (код {run.returncode})", file=sys.stderr)
    return True

def main():
    """Главная функция теста"""
    print("DEBUG: Начало теста тест_адресации_р9", file=sys.stderr)
    
    # Собираем программу
    if not build():
        clean()
        sys.exit(1)
    
    # Тестируем разные символы
    tests = [
        ('A', 65),   # Латинская A
        ('B', 66),   # Латинская B
        ('0', 48),   # Цифра 0
        ('z', 122),  # Латинская z
        ('!', 33),   # Восклицательный знак
        ('x', 120),  # Латинская x
        ('5', 53),   # Цифра 5
        ('_', 95),   # Подчёркивание
    ]
    
    all_passed = True
    
    for char, expected_code in tests:
        if not test_with_char(char, expected_code):
            all_passed = False
            break
    
    # Очищаем артефакты
    clean()
    
    if all_passed:
        print("✅ Все тесты пройдены!", file=sys.stderr)
        sys.exit(0)
    else:
        print("❌ Тест провален", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()