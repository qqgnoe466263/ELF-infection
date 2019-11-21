
all: bind_tcp.asm
	nasm -f elf32 bind_tcp.asm
	ld -m elf_i386 bind_tcp.o -o bind_tcp
