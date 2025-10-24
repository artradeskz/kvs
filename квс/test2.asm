section .text
global _start
_start:
    push qword [r8]
    pop qword [r8]
    push qword [r9] 
    pop qword [r9]
    push qword [r10]
    pop qword [r10]