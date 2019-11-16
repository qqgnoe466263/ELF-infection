#!/usr/bin/env python
from pwn import *
context.arch = 'amd64'

def shellcode():
    sh = asm("""
            push 0x41414141
            mov rax,1
            mov rdi,0
            push 0x41414141
            mov rsi,rsp
            mov rdx,4
            syscall
            pop rax
            pop rax
            call rax
            xor rax,rax
            mov rax,0x3c
            mov rdi,0
            syscall
    """)
    return sh


def sh2str(sh):
    payload = ''
    for i in range(len(sh)):
        c = str(hex(ord(sh[i])))[2:]
        if len(c) == 1:
            c = '\\x0' + c
        else:
            c = '\\x' + c
        
        payload += c
   
    return payload


payload = sh2str(shellcode())

print payload
