import tkinter as tk
from tkinter import filedialog, messagebox
import os
import subprocess
from datetime import datetime

def binary_to_disasm(input_file, output_file=None, skip_zeros=True):
    """Конвертирует бинарный файл в дизассемблированный код с помощью ndisasm."""
    try:
        # Если выходной файл не указан, создаём рядом с оригиналом
        if not output_file:
            base_name = os.path.splitext(input_file)[0]
            output_file = f"{base_name}_disasm.txt"
        
        # Вызываем ndisasm для дизассемблирования
        result = subprocess.run(
            ['ndisasm', '-b64', input_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Проверяем наличие ошибок от ndisasm
        if result.returncode != 0:
            error_msg = result.stderr.strip()
            return False, f"Ошибка ndisasm: {error_msg}"

        # Получаем текущую дату и время
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Фильтруем строки в зависимости от настройки
        lines = result.stdout.splitlines()
        if skip_zeros:
            filtered_lines = [line for line in lines if 'add [rax],al' not in line]
            filter_status = "Нули (add [rax],al) пропущены"
        else:
            filtered_lines = lines
            filter_status = "Нули (add [rax],al) не пропущены"
        
        # Записываем отфильтрованные строки в файл с заголовком
        with open(output_file, 'w', encoding='utf-8') as out_file:
            # Добавляем заголовок с информацией
            out_file.write("=" * 60 + "\n")
            out_file.write(f"Дизассемблированный код сгенерирован с помощью ndisasm\n")
            out_file.write(f"Исходный файл: {os.path.basename(input_file)}\n")
            out_file.write(f"Дата создания: {current_time}\n")
            out_file.write(f"Статус фильтра: {filter_status}\n")
            out_file.write("=" * 60 + "\n\n")
            
            for line in filtered_lines:
                out_file.write(line + '\n')
        
        return True, output_file
    
    except FileNotFoundError:
        return False, "ndisasm не найден. Убедитесь, что NASM установлен и доступен в PATH"
    except Exception as e:
        return False, str(e)

def select_and_convert():
    """Открывает диалог выбора файла и конвертирует"""
    input_file = filedialog.askopenfilename(
        title="Выберите бинарный файл",
        filetypes=(("Бинарные файлы", "*.bin *.elf *.o"), ("Все файлы", "*.*"))
    )
    
    if not input_file:
        return
    
    # Получаем состояние галочки
    skip_zeros = skip_zeros_var.get()
    
    success, result = binary_to_disasm(input_file, skip_zeros=skip_zeros)
    
    if success:
        messagebox.showinfo(
            "Готово",
            f"Файл успешно дизассемблирован!\n"
            f"Пропуск нулей: {'ВКЛ' if skip_zeros else 'ВЫКЛ'}\n"
            f"Результат сохранён как:\n{result}"
        )
    else:
        messagebox.showerror(
            "Ошибка",
            f"Не удалось дизассемблировать файл:\n{result}"
        )

def main():
    """Создаём графический интерфейс"""
    global skip_zeros_var
    
    root = tk.Tk()
    root.title("Дизассемблер бинарных файлов")
    root.geometry("500x250")
    
    # Центрируем окно
    root.eval('tk::PlaceWindow . center')
    
    # Переменная для хранения состояния галочки
    skip_zeros_var = tk.BooleanVar(value=True)  # По умолчанию включено
    
    # Создаём элементы интерфейса
    label = tk.Label(
        root,
        text="Дизассемблер бинарных файлов (ndisasm)",
        font=('Arial', 14),
        pady=20
    )
    label.pack()
    
    # Фрейм для галочки
    checkbox_frame = tk.Frame(root)
    checkbox_frame.pack(pady=10)
    
    # Галочка для пропуска нулей
    skip_zeros_check = tk.Checkbutton(
        checkbox_frame,
        text="Пропускать нули (add [rax],al)",
        variable=skip_zeros_var,
        font=('Arial', 10)
    )
    skip_zeros_check.pack()
    
    # Кнопка конвертации
    btn_convert = tk.Button(
        root,
        text="Выбрать файл и дизассемблировать",
        command=select_and_convert,
        font=('Arial', 12),
        padx=20,
        pady=10
    )
    btn_convert.pack(pady=10)
    
    # Кнопка выхода
    btn_exit = tk.Button(
        root,
        text="Выход",
        command=root.quit,
        font=('Arial', 10),
        padx=20,
        pady=5
    )
    btn_exit.pack(pady=10)
    
    root.mainloop()

if __name__ == "__main__":
    main()