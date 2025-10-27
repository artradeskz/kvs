import tkinter as tk
from tkinter import filedialog, messagebox
import os

def binary_to_hex(input_file, output_file=None, skip_zeros=False):
    """Конвертирует бинарный файл в hex-текст. Пропускает нули, если skip_zeros=True."""
    try:
        with open(input_file, 'rb') as bin_file:
            binary_data = bin_file.read()

        total_bytes = len(binary_data)

        if skip_zeros:
            filtered_data = bytes(b for b in binary_data if b != 0)
            hex_data = filtered_data.hex()
            displayed_bytes = len(filtered_data)
        else:
            hex_data = binary_data.hex()
            displayed_bytes = total_bytes

        # Форматируем с пробелами между байтами
        formatted_hex = ' '.join([hex_data[i:i+2] for i in range(0, len(hex_data), 2)])

        # Добавляем заголовок в отчёт
        report = []
        report.append(f"Исходный файл: {os.path.basename(input_file)}")
        report.append(f"Общий размер файла: {total_bytes} байт")
        if skip_zeros:
            report.append("Режим: пропускать нулевые байты (0x00)")
            report.append(f"Выведено ненулевых байт: {displayed_bytes}")
        else:
            report.append("Режим: показывать все байты (включая 0x00)")
        report.append("")
        report.append(formatted_hex)

        # Если выходной файл не указан, создаём рядом с оригиналом
        if not output_file:
            base_name = os.path.splitext(input_file)[0]
            suffix = "_hex_skip0.txt" if skip_zeros else "_hex.txt"
            output_file = f"{base_name}{suffix}"

        with open(output_file, 'w') as hex_file:
            hex_file.write('\n'.join(report))

        return True, output_file

    except Exception as e:
        return False, str(e)


def select_and_convert():
    """Открывает диалог выбора файла и конвертирует с учётом галочки."""
    input_file = filedialog.askopenfilename(
        title="Выберите бинарный файл",
        filetypes=(("Бинарные файлы", "*.elf *.bin *.out"), ("Все файлы", "*.*"))
    )

    if not input_file:
        return

    skip_zeros = skip_var.get()

    success, result = binary_to_hex(input_file, skip_zeros=skip_zeros)

    if success:
        messagebox.showinfo(
            "Готово",
            f"Файл успешно конвертирован!\nРезультат сохранён как:\n{result}"
        )
    else:
        messagebox.showerror(
            "Ошибка",
            f"Не удалось конвертировать файл:\n{result}"
        )


def main():
    """Создаём графический интерфейс"""
    root = tk.Tk()
    root.title("Бинарный в HEX конвертер")
    root.geometry("450x220")
    root.eval('tk::PlaceWindow . center')

    label = tk.Label(
        root,
        text="Конвертер бинарных файлов в HEX-текст",
        font=('Arial', 14),
        pady=10
    )
    label.pack()

    global skip_var
    skip_var = tk.BooleanVar()
    chk_skip = tk.Checkbutton(
        root,
        text="Пропускать нулевые байты (0x00)",
        variable=skip_var,
        font=('Arial', 10)
    )
    chk_skip.pack(pady=5)

    btn_convert = tk.Button(
        root,
        text="Выбрать файл и конвертировать",
        command=select_and_convert,
        font=('Arial', 12),
        padx=20,
        pady=10
    )
    btn_convert.pack(pady=10)

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