#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Тест для проверки вывода многозначного числа
Преобразует число 12345 в строку через деление на 10 и стек
Ожидаемый вывод: "12345"
"""

import subprocess
import sys
import os
from pathlib import Path

# Определяем пути
SCRIPT_DIR = Path(__file__).parent.absolute()
PROJECT_ROOT = SCRIPT_DIR.parent.parent
SOURCE_REL = SCRIPT_DIR / "вывод_многозначного.квс"

def clean():
    """Очищает артефакты сборки"""
    files = [
        "вывод_многозначного.elf",
        "вывод_многозначного.csv", 
        "вывод_многозначного.аст",
        "вывод_многозначного.токены",
        "вывод_многозначного.константа",
        "вывод_многозначного_pass4.log"
    ]
    for f in files:
        f_path = SCRIPT_DIR / f
        if f_path.exists():
            f_path.unlink()
            print(f"DEBUG: Удалён {f}", file=sys.stderr)

def build() -> bool:
    """Собирает тестовую программу с помощью КВС"""
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

def test_output() -> bool:
    """Запускает программу и проверяет вывод"""
    print("DEBUG: Запуск ELF, ожидается вывод '12345'", file=sys.stderr)
    os.chdir(SCRIPT_DIR)
    
    elf_path = SCRIPT_DIR / "вывод_многозначного.elf"
    if not elf_path.exists():
        print("❌ ELF файл не найден", file=sys.stderr)
        return False
    
    run = subprocess.run(
        [str(elf_path)], 
        capture_output=True, 
        text=True
    )
    
    expected_output = "12345"
    
    if run.stdout != expected_output:
        print(f"❌ Вывод не совпадает", file=sys.stderr)
        print(f"   Ожидалось: {repr(expected_output)}", file=sys.stderr)
        print(f"   Получено:  {repr(run.stdout)}", file=sys.stderr)
        return False
    
    if run.returncode != 0:
        print(f"❌ Код возврата: ожидался 0, получен {run.returncode}", file=sys.stderr)
        return False
    
    print(f"DEBUG: Тест пройден (вывод '{run.stdout}', код {run.returncode})", file=sys.stderr)
    return True

def main():
    """Главная функция теста"""
    print("DEBUG: Начало теста вывод_многозначного", file=sys.stderr)
    
    if not build():
        clean()
        sys.exit(1)
    
    if not test_output():
        clean()
        sys.exit(1)
    
    clean()
    print("✅ Все тесты пройдены!", file=sys.stderr)
    sys.exit(0)

if __name__ == "__main__":
    main()