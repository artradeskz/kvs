#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
квс_финсбор.py - Сборка ELF из CSV таблицы
Читает CSV, берёт колонки 'адрес' и 'рассчитанный_байт',
заполняет пропуски в адресах нулями и записывает выходной файл
"""

import sys
import csv
import os
import stat


def read_csv(csv_file):
    """Читает CSV и возвращает список адресов и байтов"""
    addresses = []
    bytes_list = []
    
    with open(csv_file, 'r', encoding='utf-8') as f:
        reader = csv.reader(f, delimiter=';')
        headers = next(reader)
        
        # Находим индексы нужных колонок
        try:
            addr_idx = headers.index('адрес')
            byte_idx = headers.index('рассчитанный_байт')
        except ValueError as e:
            print(f"Ошибка: не найдена нужная колонка в CSV: {e}")
            sys.exit(1)
        
        for row in reader:
            addr_str = row[addr_idx].strip()
            byte_str = row[byte_idx].strip()
            
            if addr_str and addr_str.startswith('0x'):
                addr = int(addr_str, 16)
                addresses.append(addr)
                
                if byte_str and byte_str.startswith('0x'):
                    bytes_list.append(int(byte_str, 16))
                else:
                    bytes_list.append(0)
    
    return addresses, bytes_list


def build_file(addresses, bytes_list, output_file):
    """Собирает файл, заполняя пропуски в адресах нулями"""
    if not addresses:
        print("Нет данных для сборки")
        return False
    
    # Определяем размер файла (максимальный адрес + 1)
    max_addr = max(addresses)
    file_size = max_addr + 1
    
    # Создаём буфер, заполненный нулями
    buffer = bytearray(file_size)
    
    # Заполняем байты по известным адресам
    for addr, byte_val in zip(addresses, bytes_list):
        buffer[addr] = byte_val
    
    # Записываем файл
    with open(output_file, 'wb') as f:
        f.write(buffer)
    
    # Добавляем права на исполнение (chmod +x)
    st = os.stat(output_file)
    os.chmod(output_file, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    
    return True


def main():
    if len(sys.argv) != 3:
        print("Использование: python kvs_builder.py <входной.csv> <выходной.elf>")
        sys.exit(1)
    
    csv_file = sys.argv[1]
    elf_file = sys.argv[2]
    
    print(f"\n=== Сборка ELF из CSV ===")
    print(f"Чтение CSV: {csv_file}")
    
    addresses, bytes_list = read_csv(csv_file)
    print(f"Найдено {len(addresses)} записей")
    
    if build_file(addresses, bytes_list, elf_file):
        print(f"\n=== Сборка завершена ===")
        print(f"  Записей в CSV: {len(addresses)}")
        print(f"  Размер файла: {max(addresses) + 1} байт (0x{max(addresses) + 1:x})")
        print(f"  Выходной файл: {elf_file}")
        print(f"\n  Исполняемый файл готов!")
        print(f"  Запустить: {elf_file}")
    else:
        print("Ошибка при сборке")
        sys.exit(1)


if __name__ == "__main__":
    main()