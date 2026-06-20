#!/usr/bin/env python3
# тесты/вычитание/вычитание.py

import subprocess
import sys
import os

PROJECT_ROOT = "../../"
SOURCE_REL = "тесты/вычитание/вычитание.квс"

def clean():
    """Удалить временные файлы"""
    files = [
        "вычитание.elf",
        "вычитание.csv",
        "вычитание.аст", 
        "вычитание.токены",
        "вычитание.константа",
        "вычитание_pass4.log"
    ]
    for f in files:
        if os.path.exists(f):
            os.remove(f)

def main():
    print("DEBUG: Начало теста вычитание", file=sys.stderr)
    
    # Переходим в корень проекта
    os.chdir(PROJECT_ROOT)
    print(f"DEBUG: Рабочая папка = {os.getcwd()}", file=sys.stderr)
    
    # 1. Сборка
    print("DEBUG: Сборка вычитание.квс", file=sys.stderr)
    build = subprocess.run(
        ["python3", "квс_сборка.py", SOURCE_REL],
        capture_output=True, text=True
    )
    
    if build.returncode != 0:
        print(f"❌ Ошибка сборки: {build.returncode}", file=sys.stderr)
        print(f"STDERR: {build.stderr}", file=sys.stderr)
        sys.exit(1)
    
    print("DEBUG: Сборка успешна", file=sys.stderr)
    
    # 2. Переходим в папку теста
    os.chdir("тесты/вычитание")
    
    # 3. Проверка ELF
    if not os.path.exists("вычитание.elf"):
        print("❌ Файл вычитание.elf не создан", file=sys.stderr)
        clean()
        sys.exit(1)
    
    # 4. Запуск
    print("DEBUG: Запуск ELF", file=sys.stderr)
    run = subprocess.run(["./вычитание.elf"], capture_output=True, text=True)
    
    print(f"DEBUG: Код возврата = {run.returncode}", file=sys.stderr)
    
    # 5. Проверка (50 - 12 = 38)
    expected = 38
    
    if run.returncode == expected:
        print(f"✅ Тест пройден: 50 - 12 = {run.returncode}", file=sys.stderr)
        clean()
        sys.exit(0)
    else:
        print(f"❌ Тест не пройден: ожидалось {expected}, получено {run.returncode}", file=sys.stderr)
        clean()
        sys.exit(1)

if __name__ == "__main__":
    main()

#1;вычитание;Тест вычитания 50-8=42
#1;вычитание_отрицательное;Тест вычитания с отрицательным результатом
#1;вычитание_память;Тест вычитания через память
#1;вычитание_цепочка;Тест последовательного вычитания