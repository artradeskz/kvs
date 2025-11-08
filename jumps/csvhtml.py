import tkinter as tk
from tkinter import filedialog, messagebox
import csv
import os

# --- Основная функция конвертации ---
def convert_csv_to_html(csv_file_path, html_file_path):
    """
    Читает semicolon-separated CSV файл и создает красивую HTML-страницу.
    Возвращает (True, сообщение) в случае успеха или (False, сообщение) в случае ошибки.
    """
    try:
        with open(csv_file_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f, delimiter=';')
            headers = reader.fieldnames
            if not headers:
                return False, "CSV-файл пуст или не имеет заголовков."
            
            rows = list(reader)

    except FileNotFoundError:
        return False, f"Файл не найден: {csv_file_path}"
    except Exception as e:
        return False, f"Ошибка при чтении CSV: {e}"

    # CSS для красивого оформления
    css_style = """
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #f4f7f6; color: #333; margin: 0; padding: 20px; }
        .container { max-width: 1400px; margin: 20px auto; background-color: #fff; padding: 25px; border-radius: 8px; box-shadow: 0 6px 12px rgba(0, 0, 0, 0.1); }
        h1 { color: #2c3e50; text-align: center; margin-bottom: 25px; }
        table { width: 100%; border-collapse: collapse; font-size: 14px; }
        th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #e0e0e0; vertical-align: top; word-wrap: break-word; }
        th { background-color: #34495e; color: #ffffff; font-weight: 600; text-transform: uppercase; font-size: 13px; }
        tr:nth-child(even) { background-color: #f8f9fa; }
        tr:hover { background-color: #e9ecef; }
        a { color: #3498db; text-decoration: none; font-weight: bold; }
        a:hover { text-decoration: underline; color: #2980b9; }
        .mono { font-family: 'Courier New', Courier, monospace; font-size: 13px; white-space: pre-wrap; }
        tr:target { background-color: #fff3cd !important; border: 2px solid #ffeaa7; animation: highlight 2s ease-in-out; }
        @keyframes highlight { from { background-color: #ffeaa7; } to { background-color: #fff3cd; } }
    </style>
    """

    # Начало HTML-документа
    html_content = f"""
    <!DOCTYPE html>
    <html lang="ru">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{os.path.basename(html_file_path)}</title>
        {css_style}
    </head>
    <body>
        <div class="container">
            <h1>Анализ дизассемблерного листинга: {os.path.basename(csv_file_path)}</h1>
            <table>
                <thead><tr>
    """
    for header in headers:
        html_content += f"<th>{header}</th>\n"
    
    html_content += "</tr></thead><tbody>\n"

    # Добавляем строки таблицы
    for row in rows:
        address = row.get('адрес', '').strip()
        target_address = row.get('целевой_адрес', '').strip()
        
        link_html = target_address
        if target_address:
            link_html = f'<a href="#{target_address}">{target_address}</a>'
        
        # Присваиваем id каждой строке на основе ее адреса
        row_id = address if address else ''
        
        html_content += f'<tr id="{row_id}">\n'
        html_content += f'<td class="mono">{address}</td>\n'
        html_content += f'<td class="mono">{row.get("байт", "")}</td>\n'
        html_content += f'<td class="mono">{link_html}</td>\n'
        html_content += f'<td>{row.get("исходная_команда", "")}</td>\n'
        html_content += "</tr>\n"

    html_content += "</tbody></table></div></body></html>"

    # Запись HTML в файл
    try:
        with open(html_file_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        return True, f"Успешно! Файл сохранен как:\n{html_file_path}"
    except Exception as e:
        return False, f"Ошибка при записи HTML файла: {e}"


# --- Функция-обработчик нажатия на кнопку ---
def open_file_and_convert():
    # Открываем диалог выбора файла
    file_path = filedialog.askopenfilename(
        title="Выберите CSV-файл для конвертации",
        filetypes=(("CSV файлы", "*.csv"), ("Все файлы", "*.*"))
    )
    
    # Если пользователь не выбрал файл, выходим
    if not file_path:
        status_label.config(text="Операция отменена.")
        return

    # Формируем имя для выходного HTML-файла
    base_name = os.path.splitext(file_path)[0]
    output_path = f"{base_name}.html"

    # Обновляем статус
    status_label.config(text="Обработка файла...")
    root.update_idletasks()  # Принудительно обновляем интерфейс

    # Вызываем функцию конвертации
    success, message = convert_csv_to_html(file_path, output_path)

    # Показываем результат
    if success:
        status_label.config(text="Готово!")
        messagebox.showinfo("Успех", message)
    else:
        status_label.config(text="Произошла ошибка.")
        messagebox.showerror("Ошибка", message)


# --- Создание графического интерфейса ---
root = tk.Tk()
root.title("CSV в HTML Конвертер")
root.geometry("450x200")  # Размер окна
root.resizable(False, False) # Запрещаем изменять размер

# Создаем фрейм для лучшего расположения элементов
main_frame = tk.Frame(root, padx=20, pady=20)
main_frame.pack(expand=True, fill=tk.BOTH)

# Кнопка "Открыть"
open_button = tk.Button(
    main_frame, 
    text="Открыть CSV-файл", 
    command=open_file_and_convert,
    width=20, 
    height=2,
    font=("Helvetica", 12)
)
open_button.pack(pady=10)

# Метка для отображения статуса
status_label = tk.Label(
    main_frame, 
    text="Нажмите кнопку, чтобы выбрать файл", 
    wraplength=400, # Перенос длинных строк
    justify=tk.CENTER
)
status_label.pack(pady=10)

# Запускаем главный цикл приложения
root.mainloop()