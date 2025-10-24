section .text
global _start
_start:
    push qword [r12]
    pop qword [r12]
    push qword [r13] 
    pop qword [r13]