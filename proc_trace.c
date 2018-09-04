/**
 * proc_trace
 * @usage proc_trace -e/p <exe>/<pid> -f <functioin>
 * @function 1. read the executable file or attach running process(need super permission).
 *           2. stop at <function> postion and print value of user regs.
 * @author HotIce0
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <elf.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/fcntl.h>
#include <sys/wait.h>
#include <linux/limits.h>

#define MODE_NONE   0
#define MODE_EXE    1
#define MODE_PID    2

typedef struct handle {
    Elf64_Ehdr *p_ehdr;
    Elf64_Phdr *p_phdr;
    Elf64_Shdr *p_shdr;
    uint8_t *p_mem;
    char *p_symname; // save the specify function name
    Elf64_Addr addr_symaddr;
    struct user_regs_struct pt_reg;
    char *exec;
}handle_t;

extern char *optarg;

Elf64_Addr lookup_symbol(handle_t *, const char *);
char * get_path_by_pid(pid_t);

int main(int argc, char * const *argv)
{
    int c, i_fd, i_pid, i_status;
    int i_mode = MODE_NONE;
    long l_orig, l_trap;
    struct stat st;
    handle_t h;

    while ((c = getopt(argc, argv, "e:p:f:")) != -1) {
        switch(c) {
            // executable
            case 'e':
                i_mode = MODE_EXE;
                // get exe path
                if ((h.exec = (char *)strdup(optarg)) == NULL) {
                    perror("strdup");
                    exit(-1);
                }
            break;
            // pid (attach)
            case 'p':
                i_mode = MODE_PID;
                i_pid = atoi(optarg);   // string to int (pid)
                // get exe path
                h.exec = get_path_by_pid(i_pid);
                if (h.exec == NULL) {
                    fprintf(stderr, "Can't retrieve executable path from pid: %d\n", i_pid);
                    exit(-1);
                }
            break;
            // function
            case 'f':
                if (i_mode == MODE_NONE) {
                    fprintf(stderr, "%s parameter-e or -p needed\n", argv[0]);
                }

                // save the symbol name
                if ((h.p_symname = strdup(optarg)) == NULL) {
                    perror("strdup");
                    exit(-1);
                }


                // open executable file
                i_fd = open(h.exec, O_RDONLY);

                // Read file status.
                if (fstat(i_fd, &st)) {
                    perror("fstat");
                    exit(-1);
                }

                // Map the executable file to memeory.
                h.p_mem = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, i_fd, 0);
                if (h.p_mem == MAP_FAILED) {
                    perror("mmap");
                    exit(-1);
                }

                h.p_ehdr = (Elf64_Ehdr *)h.p_mem;
                h.p_phdr = (Elf64_Phdr *)(h.p_mem + h.p_ehdr->e_phoff);
                h.p_shdr = (Elf64_Shdr *)(h.p_mem + h.p_ehdr->e_shoff);


                // Check the file by first 4 byte. 0x7f E L F
                if (h.p_mem[0] != 0x7f || strncmp("ELF", (char *)&h.p_mem[1], 3)) {
                    fprintf(stderr, "%s is not an ELF file\n", h.exec);
                    exit(-1);
                }

                // Check file is executable.
                if (h.p_ehdr->e_type != ET_EXEC) {
                    fprintf(stderr, "%s is not executable file\n", h.exec);
                    exit(-1);
                }

                // Check the file has the section header table.
                if (h.p_ehdr->e_shstrndx == SHN_UNDEF || h.p_ehdr->e_shoff == 0 || h.p_ehdr->e_shnum == 0) {
                    fprintf(stderr, "%s has no section header table\n", argv[1]);
                    exit(-1);
                }

                // lookup symbol address
                if ((h.addr_symaddr = lookup_symbol(&h, h.p_symname)) == 0) {
                    fprintf(stderr, "can't find the symbol %s in this executable ELF file\n", h.p_symname);
                    exit(-1);
                }
                
                // Print the symbol address.
                printf("success to find symtol %s: 0x%lx\n", h.exec, h.addr_symaddr);
                
                // Close the file
                if (close(i_fd) < 0 ) {
                    perror("close");
                    exit(-1);
                }

                // Start to debug
                if (i_mode == MODE_EXE) {
                    i_pid = fork();
                    if (i_pid == 0) {
                        // Sub process
                        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
                            perror("PTRACE_TRACEME");
                            exit(-1);
                        }
                        
                        if (execv(h.exec, argv) < 0) {
                            perror("execv");
                            exit(-1);
                        }

                        exit(0);
                    }
                    // main process
                } else {
                    // Attch to specify process
                    if (ptrace(PTRACE_ATTACH, i_pid, NULL, NULL) < 0) {
                        perror("PTRACE_ATTACH");
                        exit(-1);
                    }
                }
                // Wait the sig from sub process.
                wait(&i_status);

                // Read Orig
                l_orig = ptrace(PTRACE_PEEKTEXT, i_pid, h.addr_symaddr, NULL);
                if (errno != 0) {
                    perror("PTRACE_PEEKTEXT");
                    exit(-1);
                }

                // Create trap
                l_trap = l_orig & ~(0xFF) | 0xCC;

                // Set trap
                if (ptrace(PTRACE_POKETEXT, i_pid, h.addr_symaddr, l_trap) < 0) {
                    perror("PTRACE_POKETEXT");
                    exit(-1);
                }

                trace:
                if (ptrace(PTRACE_CONT, i_pid, NULL, NULL) < 0) {
                    perror("PTRACE_CONT");
                    exit(-1);
                }

                // wait the sub process traped && send SIG to me.
                wait(&i_status);

                // Check the reason of signal. (STOPED and SIGTRAP)
                if ( WIFSTOPPED(i_status) && WSTOPSIG(i_status) == SIGTRAP) {
                    printf("\nExecutable %s (pid=%d) has hit breakpoint 0x%lx\n",
                        h.exec,
                        i_pid,
                        h.addr_symaddr
                    );
                    // Read the user_reg
                    if (ptrace(PTRACE_GETREGS, i_pid, NULL, &h.pt_reg) < 0) {
                        perror("PTRACE_GETREGS");
                        exit(-1);
                    }
                    // Print the user_regs_struct
                    printf("%%r15: %llx\n%%r14: %llx\n%%r13: %llx\n%%r12: %llx\n"
                    "%%rbp: %llx\n%%rbx: %llx\n%%r11: %llx\n%%r10: %llx\n"
                    "%%r9: %llx\n%%r8: %llx\n%%rax: %llx\n%%rcx: %llx\n"
                    "%%rdx: %llx\n%%rsi: %llx\n%%rdi: %llx\n%%orig_rax: %llx\n"
                    "%%rip: %llx\n%%cs: %llx\n%%eflags: %llx\n%%rsp: %llx\n"
                    "%%ss: %llx\n%%fs_base: %llx\n%%gs_base: %llx\n%%ds: %llx\n"
                    "%%es: %llx\n%%fs: %llx\n%%gs: %llx\n",
                    h.pt_reg.r15, h.pt_reg.r14, h.pt_reg.r13, h.pt_reg.r12,
                    h.pt_reg.rbp, h.pt_reg.rbx, h.pt_reg.r11, h.pt_reg.r10,
                    h.pt_reg.r9, h.pt_reg.r8, h.pt_reg.rax, h.pt_reg.rcx,
                    h.pt_reg.rdx, h.pt_reg.rsi, h.pt_reg.rdi, h.pt_reg.orig_rax,
                    h.pt_reg.rip, h.pt_reg.cs, h.pt_reg.eflags, h.pt_reg.rsp,
                    h.pt_reg.ss, h.pt_reg.fs_base, h.pt_reg.gs_base, h.pt_reg.ds,
                    h.pt_reg.es, h.pt_reg.fs, h.pt_reg.gs);

                    printf("\nPlease hit any key to continue: ");
                    getchar();
                    
                    // Recover the orig (remove trap)
                    if (ptrace(PTRACE_POKETEXT, i_pid, h.addr_symaddr, l_orig) < 0) {
                        perror("PTRACE_POKETEXT");
                        exit(-1);
                    }

                    // Set the rip(Reg Instruction Point) back. (redo this instruction)
                    h.pt_reg.rip = h.pt_reg.rip - 1;

                    // Save the reg change (rip change)
                    if (ptrace(PTRACE_SETREGS, i_pid, NULL, &h.pt_reg) < 0) {
                        perror("PTRACE_SETREGS");
                        exit(-1);
                    }

                    // Set single step run and continue the process
                    if (ptrace(PTRACE_SINGLESTEP, i_pid, NULL, NULL) < 0) {
                        perror("PTRACE_SINGLESTEP");
                        exit(-1);
                    }
                    wait(NULL); // Get the singal of stopping(single step)

                    // Set trap 0xCC(int3) : soft interrupt
                    if(ptrace(PTRACE_POKETEXT, i_pid, h.addr_symaddr, l_trap) < 0) {
                        perror("PTRACE_POKETEXT");
                        exit(-1);
                    }
                    goto trace;
                }
                if (WIFEXITED(i_status))
                    printf("Completed tracing pid: %d\n", i_pid);
                exit(0);
            break;
            default:
                printf("Usage: %s -e/p <exe>/<pid> -f <functioin>\n", argv[0]);
                exit(0);
            break;
        }
    }
    printf("Usage: %s -e/p <exe>/<pid> -f <functioin>\n", argv[0]);
    exit(0);
}

/**
 * Lookup the symbol address which named [sysmname].
 * if no find, the return value is 0.
 */ 
Elf64_Addr lookup_symbol(handle_t *p_h, const char *symname)
{
    int i, j;
    char *strtab;
    Elf64_Sym *symtab;
    for (i = 0; i < p_h->p_ehdr->e_shnum; i++) {
        if (p_h->p_shdr[i].sh_type == SHT_SYMTAB) {
            printf("count of the symbol : %ld\n", p_h->p_shdr[i].sh_size / sizeof(Elf64_Sym));
            // Get the address of the symname table(.strtab).
            strtab = (char *)&p_h->p_mem[p_h->p_shdr[p_h->p_shdr[i].sh_link].sh_offset];
            printf("The index of .strtab : %d\n", p_h->p_shdr[i].sh_link);
            // Get the address of the symtab.
            symtab = (Elf64_Sym *)&p_h->p_mem[p_h->p_shdr[i].sh_offset];

            printf("strtab offset : %lx\n", p_h->p_shdr[p_h->p_shdr[i].sh_link].sh_offset);
            printf("symtab offset : %lx\n", p_h->p_shdr[i].sh_offset);

            // Lookup the symbol.
            for (j = 0; j < p_h->p_shdr[i].sh_size / sizeof(Elf64_Sym); j++) {
                // printf("%d : %s\n", j, &strtab[symtab[j].st_name]);
                if (strcmp(&strtab[symtab[j].st_name], symname) == 0)
                    return symtab[j].st_value;
            }
            
        }
    }
    printf("find the symbol failed\n");
    return 0;
}

char * get_path_by_pid(pid_t pid)
{
    char str_proc_pid_path[PATH_MAX], str_path[PATH_MAX], *p;

    if (snprintf(str_proc_pid_path, PATH_MAX, "/proc/%d/exe", pid) < 0) {
        perror("snprintf");
        exit(-1);
    }
    // readlink to get the path
    if (readlink(str_proc_pid_path, str_path, PATH_MAX) < 0) {
        perror("readlink");
        exit(-1);
    }
    if ((p = strdup(str_path)) == NULL) {
        perror("strdup");
        exit(-1);
    }
    return p;
}
