#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/ptrace.h>
#include "elf.h"
#include <link.h>

void ptrace_attach(int pid);
void ptrace_cont(int pid);
void ptrace_detach(int pid);
void *read_data(int pid ,unsigned long addr ,void *vptr ,int len);
void write_data(int pid ,unsigned long addr ,void *vptr,int len);
void resolv_tables(int pid , struct link_map *map);
unsigned long find_sym_in_tables(int pid, struct link_map *map , char *sym_name);

unsigned long   symtab;
unsigned long   strtab;
int             nchains;

struct link_map *locate_linkmap(int pid);

int main(int argc,char **argv)
{
	pid_t pid = 0;
	struct link_map *l  = malloc(sizeof(struct link_map));
	struct link_map *l1 = malloc(sizeof(struct link_map));
	struct link_map *l2 = malloc(sizeof(struct link_map));
	char *n = (char *)malloc(50);
	unsigned long addr;

	pid = atoi(argv[1]);
	printf("[+] PID : %d\n",pid);

	ptrace_attach(pid);
	l = locate_linkmap(pid);
	
	addr = (unsigned long)l->l_next;
	read_data(pid,addr,l1,sizeof(struct link_map));
	
	addr = (unsigned long)l1->l_next;
	read_data(pid,addr,l2,sizeof(struct link_map));
	
	addr = (unsigned long)l2->l_name;
	read_data(pid,addr,n,60);
	printf("[+] library : %s \n",n);

	resolv_tables(pid,l2);
	printf("[+] SYMTAB : 0x%x\n", symtab);
	printf("[+] STRTAB : 0x%x\n", strtab);
	addr = find_sym_in_tables(pid,l2,"puts");
	printf("[*] puts addr : 0x%x \n",addr);


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

/* write data to location addr */	
void write_data(int pid ,unsigned long addr ,void *vptr,int len)
{
    int i , count;
    long word;

	i = count = 0;

	while (count < len) {
		memcpy(&word , vptr+count , sizeof(word));
		word = ptrace(PTRACE_POKETEXT, pid , \
			addr+count , word);
		count +=4;
	}
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

/* search locations of DT_SYMTAB and DT_STRTAB and save them into global
 * variables, also save the nchains from hash table.
 */
void resolv_tables(int pid , struct link_map *map)
{
    Elf32_Dyn *dyn = (Elf32_Dyn *)malloc(sizeof(Elf32_Dyn));
    unsigned long addr;
	int i;

    addr = (unsigned long) map->l_ld;

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

        if(strncmp(str , sym_name , strlen(sym_name)) == 0)
            return(map->l_addr+sym->st_value);
    }
	
	free(sym);
	free(str);

    /* no symbol found, return 0 */
    return 0;
}


