#!/usr/bin/env python3
import subprocess
import sys
import os

# Пути относительно папки сложение/
PROJECT_ROOT = "../../"           # корень kvs/
SOURCE_REL = "тесты/сложение/сложение.квс"
ELF_REL = "тесты/сложение/сложение.elf"

def clean():
    """Удалить временные файлы после теста"""
    files = [
        "сложение.elf",
        "сложение.csv", 
        "сложение.аст",
        "сложение.токены",
        "сложение.константа",
        "сложение_pass4.log"
    ]
    for f in files:
        if os.path.exists(f):
            os.remove(f)
            print(f"DEBUG: Удалён {f}", file=sys.stderr)

def main():
    print("DEBUG: Начало теста сложение", file=sys.stderr)
    
    # Сохраняем текущую директорию
    original_dir = os.getcwd()
    
    # Переходим в корень проекта для сборки
    os.chdir(PROJECT_ROOT)
    print(f"DEBUG: Рабочая папка = {os.getcwd()}", file=sys.stderr)
    
    # 1. Сборка (запускаем из корня)
    print("DEBUG: Сборка сложение.квс", file=sys.stderr)
    build = subprocess.run(["python3", "квс_сборка.py", SOURCE_REL], 
                          capture_output=True, text=True)
    
    if build.returncode != 0:
        print(f"❌ Ошибка сборки: {build.returncode}", file=sys.stderr)
        print(f"STDERR: {build.stderr}", file=sys.stderr)
        print(f"STDOUT: {build.stdout}", file=sys.stderr)
        clean()
        sys.exit(1)
    
    print("DEBUG: Сборка успешна", file=sys.stderr)
    
    # Переходим в папку сложение для запуска
    os.chdir("тесты/сложение")
    print(f"DEBUG: Запуск в папке {os.getcwd()}", file=sys.stderr)
    
    # 2. Проверка, что ELF создан
    if not os.path.exists("сложение.elf"):
        print("❌ Файл сложение.elf не создан", file=sys.stderr)
        clean()
        sys.exit(1)
    
    print("DEBUG: ELF файл существует", file=sys.stderr)
    
    # 3. Запуск и проверка кода возврата
    print("DEBUG: Запуск ELF", file=sys.stderr)
    run = subprocess.run(["./сложение.elf"], capture_output=True, text=True)
    
    print(f"DEBUG: Код возврата = {run.returncode}", file=sys.stderr)
    print(f"DEBUG: stdout = {repr(run.stdout)}", file=sys.stderr)
    print(f"DEBUG: stderr = {repr(run.stderr)}", file=sys.stderr)
    
    # 4. Проверка результата (42)
    expected_code = 42
    
    if run.returncode != expected_code:
        print(f"❌ Код возврата не совпадает", file=sys.stderr)
        print(f"   Ожидалось: {expected_code}", file=sys.stderr)
        print(f"   Получено:  {run.returncode}", file=sys.stderr)
        clean()
        sys.exit(1)
    
    # Успех
    print(f"✅ Тест пройден: {run.returncode} (40+2=42)", file=sys.stderr)
    clean()
    sys.exit(0)

if __name__ == "__main__":
    main()