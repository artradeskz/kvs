#!/usr/bin/env python3
import subprocess
import sys
import os

# Пути относительно папки привет/
PROJECT_ROOT = "../../"           # корень kvs/
SOURCE_REL = "тесты/привет/привет.квс"
ELF_REL = "тесты/привет/привет.elf"

def clean():
    """Удалить временные файлы после теста"""
    files = [
        "привет.elf",
        "привет.csv", 
        "привет.аст",
        "привет.токены",
        "привет.константа",
        "привет_pass4.log"
    ]
    for f in files:
        if os.path.exists(f):
            os.remove(f)

def main():
    print("DEBUG: Начало теста привет", file=sys.stderr)
    
    # Переходим в корень проекта для сборки
    os.chdir(PROJECT_ROOT)
    print(f"DEBUG: Рабочая папка = {os.getcwd()}", file=sys.stderr)
    
    # 1. Сборка (запускаем из корня)
    print("DEBUG: Сборка привет.квс", file=sys.stderr)
    build = subprocess.run(["python3", "квс_сборка.py", SOURCE_REL], 
                          capture_output=True, text=True)
    
    if build.returncode != 0:
        print(f"❌ Ошибка сборки: {build.returncode}", file=sys.stderr)
        print(f"STDERR: {build.stderr}", file=sys.stderr)
        print(f"STDOUT: {build.stdout}", file=sys.stderr)
        clean()
        sys.exit(1)
    
    print("DEBUG: Сборка успешна", file=sys.stderr)
    
    # Возвращаемся в папку привет для запуска
    os.chdir("тесты/привет")
    
    # 2. Проверка, что ELF создан
    if not os.path.exists("привет.elf"):
        print("❌ Файл привет.elf не создан", file=sys.stderr)
        clean()
        sys.exit(1)
    
    print("DEBUG: ELF файл существует", file=sys.stderr)
    
    # 3. Запуск и проверка
    print("DEBUG: Запуск ELF", file=sys.stderr)
    run = subprocess.run(["./привет.elf"], capture_output=True, text=True)
    
    print(f"DEBUG: Код возврата = {run.returncode}", file=sys.stderr)
    print(f"DEBUG: stdout = {repr(run.stdout)}", file=sys.stderr)
    
    # Проверка вывода
    expected_output = "Привет мир!\n"
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