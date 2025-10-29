section .text
global _start

_start:
    ; Подготовка флагов через сравнение
    mov rax, 5
    mov rbx, 5
    cmp rax, rbx        ; устанавливает ZF = 1

    ; je / jz — короткий переход если равно / ноль
    je .label_je

    ; Если не сработал — ошибка (но он сработает)
    mov rdi, 1
    mov rax, 60         ; sys_exit
    syscall

.label_je:
    mov rax, 10
    mov rbx, 20
    cmp rax, rbx        ; ZF = 0, SF ≠ OF → jl сработает

    ; jl — короткий переход если меньше
    jl .label_jl
    mov rdi, 2
    mov rax, 60
    syscall

.label_jl:
    ; jg — короткий переход если больше
    mov rax, 30
    mov rbx, 20
    cmp rax, rbx        ; rax > rbx → jg должен сработать
    jg .label_jg
    mov rdi, 3
    mov rax, 60
    syscall

.label_jg:
    ; jle — меньше или равно
    mov rax, 15
    mov rbx, 15
    cmp rax, rbx        ; равно → jle сработает
    jle .label_jle
    mov rdi, 4
    mov rax, 60
    syscall

.label_jle:
    ; jge — больше или равно
    mov rax, 100
    mov rbx, 50
    cmp rax, rbx        ; больше → jge сработает
    jge .label_jge
    mov rdi, 5
    mov rax, 60
    syscall

.label_jge:
    ; jc — переход если перенос (CF=1)
    ; Установим CF через вычитание
    mov rax, 5
    mov rbx, 10
    cmp rax, rbx        ; 5 < 10 → CF = 1
    jc .label_jc
    mov rdi, 6
    mov rax, 60
    syscall

.label_jc:
    ; jnc — переход если нет переноса
    mov rax, 10
    mov rbx, 5
    cmp rax, rbx        ; CF = 0
    jnc .label_jnc
    mov rdi, 7
    mov rax, 60
    syscall

.label_jnc:
    ; jne — переход если не равно
    mov rax, 1
    mov rbx, 2
    cmp rax, rbx        ; не равно → ZF=0 → jne сработает
    jne .label_jne
    mov rdi, 8
    mov rax, 60
    syscall

.label_jne:
    ; Безусловный короткий переход
    jmp .label_done

    ; Если сюда попали — ошибка
    mov rdi, 9
    mov rax, 60
    syscall

.label_done:
    ; Успешный выход
    mov rdi, 0
    mov rax, 60         ; sys_exit
    syscall