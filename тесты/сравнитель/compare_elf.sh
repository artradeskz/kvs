#!/bin/bash

# Сравнение ELF-файлов побайтно
# Сохраняет отчёт в файл
# Нужен для проверки совместимости нового компилятора с 8й версией

if [ $# -ne 2 ]; then
    echo "Использование: $0 <файл1.elf> <файл2.elf>"
    exit 1
fi

FILE1="$1"
FILE2="$2"
OUTPUT="compare_$(basename "$1")_$(basename "$2").txt"

echo "Сравнение: $FILE1 vs $FILE2"
echo "Отчёт: $OUTPUT"

# Заголовок отчёта
{
    echo "========================================"
    echo "ПОБАЙТНОЕ СРАВНЕНИЕ ELF-ФАЙЛОВ"
    echo "========================================"
    echo "Файл 1: $FILE1"
    echo "Файл 2: $FILE2"
    echo "Время: $(date)"
    echo "========================================"
    echo ""
    
    # Размеры файлов
    SIZE1=$(stat -c %s "$FILE1")
    SIZE2=$(stat -c %s "$FILE2")
    echo "Размер файла 1: $SIZE1 байт"
    echo "Размер файла 2: $SIZE2 байт"
    echo ""
    
    if [ "$SIZE1" -ne "$SIZE2" ]; then
        echo "ВНИМАНИЕ: Размеры файлов отличаются!"
        echo ""
    fi
    
    # Побайтное сравнение
    echo "ПОБАЙТНОЕ СРАВНЕНИЕ:"
    echo "--------------"
    
    # Используем cmp для побайтного сравнения
    cmp -l "$FILE1" "$FILE2" 2>/dev/null | while read offset byte1 byte2; do
        echo "Смещение 0x$(printf "%08x" $((offset-1))): байт1=0x$byte1, байт2=0x$byte2"
    done
    
    DIFF_COUNT=$(cmp -l "$FILE1" "$FILE2" 2>/dev/null | wc -l)
    
    if [ "$DIFF_COUNT" -eq 0 ]; then
        echo "Файлы идентичны!"
    else
        echo ""
        echo "Всего различий: $DIFF_COUNT"
    fi
    
    echo ""
    echo "========================================"
    echo "СРАВНЕНИЕ ELF-ЗАГОЛОВКОВ"
    echo "========================================"
    
    # Сравнение ELF-заголовков
    echo ""
    echo "--- readelf -h ---"
    echo "=== $FILE1 ===" >> /tmp/elf1_header.txt
    readelf -h "$FILE1" 2>/dev/null >> /tmp/elf1_header.txt
    echo "=== $FILE2 ===" >> /tmp/elf2_header.txt
    readelf -h "$FILE2" 2>/dev/null >> /tmp/elf2_header.txt
    diff /tmp/elf1_header.txt /tmp/elf2_header.txt 2>/dev/null || echo "ELF-заголовки отличаются"
    rm -f /tmp/elf1_header.txt /tmp/elf2_header.txt
    
    echo ""
    echo "--- readelf -l (программные заголовки) ---"
    echo "=== $FILE1 ===" >> /tmp/elf1_ph.txt
    readelf -l "$FILE1" 2>/dev/null >> /tmp/elf1_ph.txt
    echo "=== $FILE2 ===" >> /tmp/elf2_ph.txt
    readelf -l "$FILE2" 2>/dev/null >> /tmp/elf2_ph.txt
    diff /tmp/elf1_ph.txt /tmp/elf2_ph.txt 2>/dev/null || echo "Программные заголовки отличаются"
    rm -f /tmp/elf1_ph.txt /tmp/elf2_ph.txt
    
    echo ""
    echo "--- readelf -S (секции) ---"
    echo "=== $FILE1 ===" >> /tmp/elf1_sec.txt
    readelf -S "$FILE1" 2>/dev/null >> /tmp/elf1_sec.txt
    echo "=== $FILE2 ===" >> /tmp/elf2_sec.txt
    readelf -S "$FILE2" 2>/dev/null >> /tmp/elf2_sec.txt
    diff /tmp/elf1_sec.txt /tmp/elf2_sec.txt 2>/dev/null || echo "Секции отличаются"
    rm -f /tmp/elf1_sec.txt /tmp/elf2_sec.txt
    
    echo ""
    echo "========================================"
    echo "HEX-ДАМП ПЕРВЫХ 256 БАЙТ"
    echo "========================================"
    echo ""
    echo "=== $FILE1 ==="
    hexdump -C "$FILE1" -n 256
    echo ""
    echo "=== $FILE2 ==="
    hexdump -C "$FILE2" -n 256
    
    echo ""
    echo "========================================"
    echo "HEX-ДАМП ОБЛАСТИ ПРОГРАММНЫХ ЗАГОЛОВКОВ (0x40-0xe8)"
    echo "========================================"
    echo ""
    echo "=== $FILE1 ==="
    hexdump -C "$FILE1" -s 0x40 -n 168
    echo ""
    echo "=== $FILE2 ==="
    hexdump -C "$FILE2" -s 0x40 -n 168
    
    echo ""
    echo "========================================"
    echo "HEX-ДАМП ОБЛАСТИ ТАБЛИЦЫ СЕКЦИЙ (0x2040-0x2140)"
    echo "========================================"
    echo ""
    echo "=== $FILE1 ==="
    hexdump -C "$FILE1" -s 0x2040 -n 256 2>/dev/null || echo "Нет данных по адресу 0x2040"
    echo ""
    echo "=== $FILE2 ==="
    hexdump -C "$FILE2" -s 0x2040 -n 256 2>/dev/null || echo "Нет данных по адресу 0x2040"
    
    echo ""
    echo "========================================"
    echo "СРАВНЕНИЕ ВЫПОЛНЕНИЯ"
    echo "========================================"
    
    echo "=== Выполнение $FILE1 ==="
    ./"$FILE1"
    echo "Код возврата: $?"
    
    echo "=== Выполнение $FILE2 ==="
    ./"$FILE2"
    echo "Код возврата: $?"

} > "$OUTPUT"

echo "Отчёт сохранён в: $OUTPUT"

# Показать количество различий
DIFF_COUNT=$(cmp -l "$FILE1" "$FILE2" 2>/dev/null | wc -l)
if [ "$DIFF_COUNT" -eq 0 ]; then
    echo "✅ Файлы идентичны!"
else
    echo "❌ Найдено $DIFF_COUNT различий"
fi