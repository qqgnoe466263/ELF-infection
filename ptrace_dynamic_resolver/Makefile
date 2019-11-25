
all: test.c hello.c
	gcc -m32 test.c -o test -g 
	gcc -m32 hello.c -o hello -fno-stack-protector -Wl,-dynamic-linker /home/vagrant/STCS/glibc-2.23/32/lib/ld-2.23.so -g
