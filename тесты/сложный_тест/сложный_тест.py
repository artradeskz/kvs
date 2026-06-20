#!/usr/bin/env python3
import subprocess
import sys
import os

# Пути относительно папки сложный_тест/
PROJECT_ROOT = "../../"           # корень kvs/
SOURCE_REL = "тесты/сложный_тест/сложный_тест.квс"

def clean():
    """Удалить временные файлы после теста"""
    files = [
        "сложный_тест.elf",
        "сложный_тест.csv", 
        "сложный_тест.аст",
        "сложный_тест.токены",
        "сложный_тест.константа",
        "сложный_тест_pass4.log"
    ]
    for f in files:
        if os.path.exists(f):
            os.remove(f)

def main():
    print("DEBUG: Начало теста сложный_тест", file=sys.stderr)
    
    # Переходим в корень проекта для сборки
    os.chdir(PROJECT_ROOT)
    print(f"DEBUG: Рабочая папка = {os.getcwd()}", file=sys.stderr)
    
    # 1. Сборка
    print("DEBUG: Сборка сложный_тест.квс", file=sys.stderr)
    build = subprocess.run(["python3", "квс_сборка.py", SOURCE_REL], 
                          capture_output=True, text=True)
    
    if build.returncode != 0:
        print(f"❌ Ошибка сборки: {build.returncode}", file=sys.stderr)
        print(f"STDERR: {build.stderr}", file=sys.stderr)
        print(f"STDOUT: {build.stdout}", file=sys.stderr)
        clean()
        sys.exit(1)
    
    print("DEBUG: Сборка успешна", file=sys.stderr)
    
    # Возвращаемся в папку сложный_тест для запуска
    os.chdir("тесты/сложный_тест")
    
    # 2. Проверка, что ELF создан
    if not os.path.exists("сложный_тест.elf"):
        print("❌ Файл сложный_тест.elf не создан", file=sys.stderr)
        clean()
        sys.exit(1)
    
    print("DEBUG: ELF файл существует", file=sys.stderr)
    
    # 3. Запуск и проверка
    print("DEBUG: Запуск ELF", file=sys.stderr)
    run = subprocess.run(["./сложный_тест.elf"], capture_output=True, text=True)
    
    print(f"DEBUG: Код возврата = {run.returncode}", file=sys.stderr)
    print(f"DEBUG: stdout = {repr(run.stdout)}", file=sys.stderr)
    
    # Проверка вывода (должно быть два сообщения: "Живой из 3!" и "Успех!")
    expected_output = "Живой из 3!\nУспех!\n\x00"
    
    if run.stdout != expected_output:
        print(f"❌ Вывод не совпадает", file=sys.stderr)
        print(f"   Ожидалось: {repr(expected_output)}", file=sys.stderr)
        print(f"   Получено:  {repr(run.stdout)}", file=sys.stderr)
        clean()
        sys.exit(1)
    
    # Проверка кода возврата
    if run.returncode != 0:
        print(f"❌ Код возврата: ожидался 0, получен {run.returncode}", file=sys.stderr)
        clean()
        sys.exit(1)
    
    # Успех
    print("✅", file=sys.stderr)
    clean()
    sys.exit(0)

if __name__ == "__main__":
    main()