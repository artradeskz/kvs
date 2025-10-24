section .text
global _start
_start:
    ; Простые случаи с разными базовыми регистрами
    push qword [rax]
    pop qword [rax]
    
    push qword [rbx]
    pop qword [rbx]
    
    push qword [rsp]
    pop qword [rsp]
    
    push qword [rbp]
    pop qword [rbp]
    
    ;mov rax, 60
    ;mov rdi, 0  
    ;syscall