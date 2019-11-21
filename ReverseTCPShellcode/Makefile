
all: RevTCPShell.asm RevTCPShell.c RevTCPShellpoc.c
	nasm -f elf32 RevTCPShell.asm
	ld -m elf_i386 RevTCPShell.o -o RevTCPShellasm
	gcc -m32 RevTCPShell.c -o RevTCPShell
	gcc -m32 -fno-stack-protector -z execstack RevTCPShellpoc.c -o RevTCPShellpoc
