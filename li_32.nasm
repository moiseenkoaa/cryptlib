;extern "C"
;{
;    int __fastcall my_htonl(_IP x);
;}
;
section .data
section .bss
section .text
;;	global m11	
;	global ?m11@@YAHXZ
;?m11@@YAHXZ:
;;m11:
;	mov eax, 12345
;	ret
;
;	global my_htonl22
my_htonl22:
;mov eax, 0F0000000h
;or eax, eax
;add eax, 020000000h
;test eax, eax
;inc eax
    mov eax, ecx
    bswap eax
    ret
