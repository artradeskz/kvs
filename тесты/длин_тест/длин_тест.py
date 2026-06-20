#!/usr/bin/env python3
import subprocess
import sys
import os

# Пути относительно папки длин_тест/
PROJECT_ROOT = "../../"
SOURCE_REL = "тесты/длин_тест/длин_тест.квс"

def clean():
    """Удалить временные файлы после теста"""
    files = [
        "длин_тест.elf",
        "длин_тест.csv", 
        "длин_тест.аст",
        "длин_тест.токены",
        "длин_тест.константа",
        "длин_тест_pass4.log"
    ]
    for f in files:
        if os.path.exists(f):
            os.remove(f)

def main():
    print("DEBUG: Начало теста длин_тест", file=sys.stderr)
    
    os.chdir(PROJECT_ROOT)
    print(f"DEBUG: Рабочая папка = {os.getcwd()}", file=sys.stderr)
    
    # 1. Сборка
    print("DEBUG: Сборка длин_тест.квс", file=sys.stderr)
    build = subprocess.run(["python3", "квс_сборка.py", SOURCE_REL], 
                          capture_output=True, text=True)
    
    if build.returncode != 0:
        print(f"❌ Ошибка сборки: {build.returncode}", file=sys.stderr)
        print(f"STDERR: {build.stderr}", file=sys.stderr)
        clean()
        sys.exit(1)
    
    print("DEBUG: Сборка успешна", file=sys.stderr)
    
    os.chdir("тесты/длин_тест")
    
    if not os.path.exists("длин_тест.elf"):
        print("❌ Файл длин_тест.elf не создан", file=sys.stderr)
        clean()
        sys.exit(1)
    
    print("DEBUG: Запуск ELF", file=sys.stderr)
    run = subprocess.run(["./длин_тест.elf"], capture_output=True, text=True)
    
    print(f"DEBUG: Код возврата = {run.returncode}", file=sys.stderr)
    print(f"DEBUG: stdout = {repr(run.stdout)}", file=sys.stderr)
    
    # Ожидаемый вывод (с \x00, как в сложном_тесте)
    expected_output = "Живой из 3!Успех!\n"
    
    if run.stdout != expected_output:
        print(f"❌ Вывод не совпадает", file=sys.stderr)
        print(f"   Ожидалось: {repr(expected_output)}", file=sys.stderr)
        print(f"   Получено:  {repr(run.stdout)}", file=sys.stderr)
        clean()
        sys.exit(1)
    
    if run.returncode != 0:
        print(f"❌ Код возврата: ожидался 0, получен {run.returncode}", file=sys.stderr)
        clean()
        sys.exit(1)
    
    print("✅", file=sys.stderr)
    clean()
    sys.exit(0)

if __name__ == "__main__":
    main()