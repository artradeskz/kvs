#!/usr/bin/env python3
import subprocess
import sys
import csv
from pathlib import Path

def main():
    # Диспетчер лежит в тесты/прогон_тестов.py
    # Значит, корень с табличкой — та же папка (тесты/)
    tests_dir = Path(__file__).parent
    csv_file = tests_dir / "kvs_full_test.csv"
    
    if not csv_file.exists():
        print(f"❌ Нет файла {csv_file}")
        print("   Создайте его с колонками: активен;папка;описание")
        sys.exit(1)
    
    passed = 0
    failed = 0
    skipped = 0
    results = []
    
    # Читаем табличку
    with open(csv_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f, delimiter=';')
        for row in reader:
            active = row.get('активен', '0').strip()
            folder = row.get('папка', '').strip()
            description = row.get('описание', '').strip()
            
            if not folder:
                continue
                
            if active != '1':
                print(f"\n⏭️ {folder}: пропуск (отключён)")
                skipped += 1
                continue
            
            test_dir = tests_dir / folder
            checker = test_dir / f"{folder}.py"
            
            if not test_dir.exists():
                print(f"\n❌ {folder}: папка не найдена")
                failed += 1
                results.append((folder, "FAIL", "папка отсутствует"))
                continue
            
            if not checker.exists():
                print(f"\n❌ {folder}: нет {folder}.py")
                failed += 1
                results.append((folder, "FAIL", "нет проверяльщика"))
                continue
            
            # Запуск теста
            print(f"\n📝 {folder}: {description}")
            print("   ", end="", flush=True)
            
            result = subprocess.run([sys.executable, checker], 
                                   cwd=test_dir,
                                   capture_output=True, 
                                   text=True)
            
            if result.returncode == 0:
                print("✅")
                passed += 1
                results.append((folder, "PASS", ""))
            else:
                print("❌")
                failed += 1
                # Показываем ВСЮ отладочную информацию
                print(f"\n   --- stdout теста ---")
                if result.stdout:
                    for line in result.stdout.strip().split('\n'):
                        print(f"   {line}")
                else:
                    print("   (пусто)")
                print(f"   --- stderr теста ---")
                if result.stderr:
                    for line in result.stderr.strip().split('\n'):
                        print(f"   {line}")
                else:
                    print("   (пусто)")
                print(f"   --------------------")
                results.append((folder, "FAIL", result.stderr.strip().split('\n')[0] if result.stderr else "ошибка"))
    
    # Итоги
    print(f"\n{'='*50}")
    print(f"✅ Пройдено: {passed}")
    print(f"❌ Провалено: {failed}")
    print(f"⏭️ Пропущено: {skipped}")
    
    if failed > 0:
        print(f"\nПроваленные тесты:")
        for name, status, msg in results:
            if status == "FAIL":
                print(f"  • {name}: {msg}")
        sys.exit(1)
    else:
        print(f"\n🎉 Все активные тесты пройдены!")
        sys.exit(0)

if __name__ == "__main__":
    # Очистка перед запуском (отключено, чтобы не удалять табличку)
    # subprocess.run([sys.executable, "cleaner.py"], 
    #                cwd=Path(__file__).parent,
    #                capture_output=True)
    main()