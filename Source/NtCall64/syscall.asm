;*******************************************************************************
;
;  (C) COPYRIGHT AUTHORS, 2016 - 2026
;
;  TITLE:       SYSCALL.ASM
;
;  VERSION:     2.10
;
;  DATE:        15 Aug 2026
;
;  Syscall gate implementation.
;
; THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
; ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
; TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
; PARTICULAR PURPOSE.
;
;*******************************************************************************/

public ntSyscallGate

_TEXT$00 segment para 'CODE'

    ALIGN 16
    PUBLIC ntSyscallGate

; param 1 (rcx) service ID
; param 2 (rdx) service arguments count
; param 3 (r8) pointer to array of arguments

ntSyscallGate PROC
    push rbx
    push rdi
    push r12
    push r13
    push r14
    push r15

    mov r15, rsp
    mov r12, rcx
    mov r13, rdx
    mov r14, r8

    xor ebx, ebx
    cmp r13, 4
    jbe ntGateNoExtraArgs

    mov rbx, r13
    sub rbx, 4

ntGateNoExtraArgs:
    lea rax, [rbx*8+28h]
    add rax, 0Fh
    and rax, -10h
    sub rsp, rax

    cmp rbx, 0
    je ntGateInvoke

    xor rdi, rdi
ntGateFillStack:
    mov rax, [r14+20h+rdi*8]
    mov [rsp+28h+rdi*8], rax
    inc rdi
    cmp rdi, rbx
    jb ntGateFillStack

ntGateInvoke:
    mov rax, r12
    mov rcx, [r14]
    mov rdx, [r14+08h]
    mov r8,  [r14+10h]
    mov r9,  [r14+18h]
    mov r10, rcx
    syscall

    mov rsp, r15
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rbx
    ret
ntSyscallGate ENDP

_TEXT$00 ENDS

END
