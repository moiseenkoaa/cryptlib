; Unix:  RDI, RSI, RDX, RCX, R8, R9
; Win64: RCX, RDX, R8, R9
;
; Unix used:  RDI, RSI, RDX, RCX, R8, R9, RAX, R10, R11
; Win64 used: RCX, RDX, R8, R9, RAX, R10, R11
;
; linux2win64 stub 4:
; mov r8, rdx
; mov r9, rcx
; mov rcx, rdi
; mov rdx, rsi
; ...
;
; linux2win64 stub 5:
; mov r10, r8
; mov r8, rdx
; mov r9, rcx
; mov rcx, rdi
; mov rdx, rsi
; jmp LongInt2_mul_000
;LongInt2_mul:
;  mov r10, [rsp + 28h] ; Mul2
;LongInt2_mul_000:
;
;extern "C"
;{
;    int __fastcall my_htonl(_IP x);
;}
;
section .data
section .bss
section .text
;
;;	global m11	
;	global ?m11@@YAHXZ
;?m11@@YAHXZ:
;;m11:
;	mov eax, 12345
;	ret
;
;	global my_htonl
;my_htonl:
;mov eax, 0F0000000h
;or eax, eax
;add eax, 020000000h
;test eax, eax
;inc eax
;    mov eax, ecx
;    bswap eax
;    ret
;
;
;Соглашения о связях
;; System V AMD64
;Необходимо сохранять RBP, RBX, R12, R13, R14, R15.
;При использовании инструкций MMX требуется выполнить FEMMS.
;Флаг DF должен быть сброшен.
;Управляющие биты MXCSR и FPU сохраняет вызываемый.
;Статусные биты MXCSR и FPU сохраняет вызывающий.
;; Microsoft:
;Необходимо сохранять RBP, RBX, RSI, RDI, R12, R13, R14, R15, XMM6..XMM15.
;Флаг DF должен быть сброшен.
;Управляющие биты MXCSR и FPU сохраняет вызываемый.
;Статусные биты MXCSR и FPU сохраняет вызывающий.
;
               global LongInt2_add_unix
LongInt2_add_unix:
 mov r8, rdx
 mov r9, rcx
 mov rcx, rdi
 mov rdx, rsi
               global LongInt2_add_win
LongInt2_add_win:
;extern "C"
;{
;    _dword LongInt2_add(_qword sz8, _qword up8, void* dst, const void* src) noexcept;
;}
;   rcx - sz8
;   rdx - up8
;   r8  - dst
;   r9  - src
               or  rcx, rcx
               jz  LongInt2_add_Exit1
;align 8
LongInt2_add_Loop1:
               mov rax, [r9]
               adc [r8], rax
               lea r9, [r9 + 8]
               lea r8, [r8 + 8]
               loop LongInt2_add_Loop1
LongInt2_add_Exit1:
               mov eax, ecx
               jnc LongInt2_add_Exit3
               mov rcx, rdx
               inc rcx
               dec rcx
               jz  LongInt2_add_Exit2
;align 8
LongInt2_add_Loop2:
               adc [r8], rax
               lea r8, [r8 + 8]
               loop LongInt2_add_Loop2
LongInt2_add_Exit2:
               rcl al, 1
LongInt2_add_Exit3:
               ret
;
               global LongInt2_sub_unix
LongInt2_sub_unix:
 mov r8, rdx
 mov r9, rcx
 mov rcx, rdi
 mov rdx, rsi
               global LongInt2_sub_win
LongInt2_sub_win:
;    _dword LongInt2_sub(_qword sz8, _qword up8, void* dst, const void* src);
;   rcx - sz8
;   rdx - up8
;   r8  - dst
;   r9  - src
               or  rcx, rcx
               jz  LongInt2_sub_Exit1
;align 8
LongInt2_sub_Loop1:
               mov rax, [r9]
               sbb [r8], rax
               lea r9, [r9 + 8]
               lea r8, [r8 + 8]
               loop LongInt2_sub_Loop1
LongInt2_sub_Exit1:
               mov eax, ecx
               jnc LongInt2_sub_Exit3
               mov rcx, rdx
               inc rcx
               dec rcx
               jz  LongInt2_sub_Exit2
;align 8
LongInt2_sub_Loop2:
               sbb [r8], rax
               lea r8, [r8 + 8]
               loop LongInt2_sub_Loop2
LongInt2_sub_Exit2:
               rcl al, 1
LongInt2_sub_Exit3:
               ret
;
               global LongInt2_mul_unix
LongInt2_mul_unix:
 mov r10, r8
 mov r8, rdx
 mov r9, rcx
 mov rcx, rdi
 mov rdx, rsi
 jmp LongInt2_mul_000
               global LongInt2_mul_win
LongInt2_mul_win:
;extern "C"
;{
; void LongInt2_mul(_qword Mul1SizeQw, _qword Mul2SizeQw, void * Product, const void * Mul1, const void * Mul2) noexcept;
;}
;   rcx - Mul1SizeQw
;   rdx - Mul2SizeQw
;   r8 - Product
;   r9 - Mul1
;   [rsp + 28h] - Mul2
;
               mov r10, [rsp + 28h] ; Mul2
LongInt2_mul_000:
               push rbx ; +
               push rsi ; +
               push rdi ; +
               push r12 ; +
               push r13 ; +
               push r14 ; +
               push r15 ; +
 
               xor r13, r13 ; r13 == 0
               mov r14, 8   ; r14 == 8
               mov rdi, r8 ; dst
               mov r11, rcx ; Mul1SizeQw
               mov r12, rdx ; Mul2SizeQw; храним в r12 mul2size
LongInt2_MulLoop0:
               mov rbx, [r10]
               add r10, r14
               mov rsi, r9 ; rax
               mov rcx, r11
               xor rdx, rdx
;align 8
LongInt2_MulLoop1:
               mov r15, rdx
               mov rax, rbx
               mul qword[rsi]
               add rax, r15
               adc rdx, r13
               add [rdi], rax
               adc rdx, r13
               add rsi, r14
               add rdi, r14
               loop LongInt2_MulLoop1

               mov[rdi], rdx
               lea r8, [r8 + r14]
               mov rdi, r8
               dec r12
               jnz LongInt2_MulLoop0 ; loop
;
               pop r15 ; +
               pop r14 ; +
               pop r13 ; +
               pop r12 ; +
               pop rdi ; +
               pop rsi ; +
               pop rbx ; +
               ret
;
;
               global ConstMemcmp_unix
ConstMemcmp_unix:
; (RDI, RSI, RDX)
 mov r8, rdx
 mov rcx, rdi
 mov rdx, rsi
               global ConstMemcmp_win
ConstMemcmp_win:
; (RCX, RDX, R8)
; Необходимо сохранять RBX, RSI, RDI, RBP, R12, R13, R14, R15, XMM6..XMM15.
; Win64 can be used: RCX, RDX, R8, R9, RAX, R10, R11
;extern "C"
;{
;   _dword ConstMemcmp_win(const void * p1, const void * p2, size_t len) noexcept;
;}
;   rcx - p1
;   rdx - p2
;   r8  - len
               mov r11, rsi ; save rsi
               mov r10, rdi ; save rdi
               mov rsi, rcx
               mov rdi, rdx
               mov r9, r8
               xor ecx, ecx
               shr r9, 4 ; mod ZF
               jz  ConstMemcmp_SkipLoop1
ConstMemcmp_Loop1:
               mov rax, [rsi]
               xor rax, [rdi]
               or rcx, rax
               mov rax, [rsi + 8]
               xor rax, [rdi + 8]
               or rcx, rax
               lea rsi, [rsi + 10h]
               lea rdi, [rdi + 10h]
               dec r9
               jnz ConstMemcmp_Loop1
               mov eax, ecx
               shr rcx, 32
               or  ecx, eax
ConstMemcmp_SkipLoop1:
               mov r9d, r8d
               shr r9d, 2
               and r9d, 3
               jz  ConstMemcmp_SkipLoop2
ConstMemcmp_Loop2:
               mov eax, [rsi]
               xor eax, [rdi]
               or ecx, eax
               lea rsi, [rsi + 4]
               lea rdi, [rdi + 4]
               dec r9d
               jnz ConstMemcmp_Loop2
ConstMemcmp_SkipLoop2:
               and r8d, 3
               jz  ConstMemcmp_Exit1
ConstMemcmp_Loop3:
               mov al, [rsi]
               xor al, [rdi]
               or cl, al
               ;lea rsi, [rsi + 1]
               ;lea rdi, [rdi + 1]
               inc rsi
               inc rdi
               dec r8d
               jnz ConstMemcmp_Loop3
ConstMemcmp_Exit1:
               mov eax, ecx
               mov rdi, r10 ; restore rdi
               mov rsi, r11 ; restore rsi
               ret
;
