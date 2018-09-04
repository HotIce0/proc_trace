# proc_trace by HotIce0
## Usage : `proc_trace -e/p <exe>/<pid> -f <functioin>`
## Require : Linux 64bit and the program must be ELF executable type. (add gcc parrament -static => `gcc -static -o test test.c`)
## Function : 
1. read the executable file or attach running process(need super permission).
2. stop at <function> postion and print value of user regs.
# Demo
1. file[test.c]

```c
#include <stdio.h>
#include <unistd.h>
void hotice0(int i)
{
    printf("i am hotice0 like %d\n", i);
}

int main(void)
{
    int i;
    for (i = 0; i < 10; i++) {
        hotice0(7);
        sleep(3);
    }
    hotice0(77);
    return 0;
}
```

2. Compile
  `$ gcc -static -o test test.c`
  
3. Run Results

  1. run the test
  `$ ./test `
  
  2. get pid
  
    ```
    zg@ubuntu:~/Documents/trace/getopt_demo$ ps -a |grep test
    24745 pts/0    00:00:00 test
    ```
    
  3. start to dubug(need super user permisstion)
  
  ```shell
	root@ubuntu:/home/zg/Documents/trace/getopt_demo# ./proc_trace -p 24745 -f hotice0
	count of the symbol : 1813
	The index of .strtab : 31
	strtab offset : c71c0
	symtab offset : bc7c8
	success to find symtol /home/zg/Documents/trace/getopt_demo/test: 0x400b4d

	Executable /home/zg/Documents/trace/getopt_demo/test (pid=24745) has hit breakpoint 0x400b4d
	%r15: 0
	%r14: 6b9018
	%r13: 0
	%r12: 401930
	%rbp: 7ffeefd2ff20
	%rbx: 400400
	%r11: 246
	%r10: 0
	%r9: 14
	%r8: 0
	%rax: 0
	%rcx: 448be1
	%rdx: 0
	%rsi: 7ffeefd2fed0
	%rdi: 7
	%orig_rax: ffffffffffffffff
	%rip: 400b4e
	%cs: 33
	%eflags: 297
	%rsp: 7ffeefd2ff08
	%ss: 2b
	%fs_base: 1ab8880
	%gs_base: 0
	%ds: 0
	%es: 0
	%fs: 0
	%gs: 0

	Please hit any key to continue: 

	Executable /home/zg/Documents/trace/getopt_demo/test (pid=24745) has hit breakpoint 0x400b4d
	%r15: 0
	%r14: 6b9018
	%r13: 0
	%r12: 401930
	%rbp: 7ffeefd2ff20
	%rbx: 400400
	%r11: 246
	%r10: 0
	%r9: 14
	%r8: 0
	%rax: 0
	%rcx: 448be1
	%rdx: 0
	%rsi: 7ffeefd2fed0
	%rdi: 7
	%orig_rax: ffffffffffffffff
	%rip: 400b4e
	%cs: 33
	%eflags: 293
	%rsp: 7ffeefd2ff08
	%ss: 2b
	%fs_base: 1ab8880
	%gs_base: 0
	%ds: 0
	%es: 0
	%fs: 0
	%gs: 0

	Please hit any key to continue: 

	Executable /home/zg/Documents/trace/getopt_demo/test (pid=24745) has hit breakpoint 0x400b4d
	%r15: 0
	%r14: 6b9018
	%r13: 0
	%r12: 401930
	%rbp: 7ffeefd2ff20
	%rbx: 400400
	%r11: 246
	%r10: 0
	%r9: 14
	%r8: 0
	%rax: 0
	%rcx: 448be1
	%rdx: 0
	%rsi: 7ffeefd2fed0
	%rdi: 7
	%orig_rax: ffffffffffffffff
	%rip: 400b4e
	%cs: 33
	%eflags: 297
	%rsp: 7ffeefd2ff08
	%ss: 2b
	%fs_base: 1ab8880
	%gs_base: 0
	%ds: 0
	%es: 0
	%fs: 0
	%gs: 0

	Please hit any key to continue: 

	Executable /home/zg/Documents/trace/getopt_demo/test (pid=24745) has hit breakpoint 0x400b4d
	%r15: 0
	%r14: 6b9018
	%r13: 0
	%r12: 401930
	%rbp: 7ffeefd2ff20
	%rbx: 400400
	%r11: 246
	%r10: 0
	%r9: 14
	%r8: 0
	%rax: 0
	%rcx: 448be1
	%rdx: 0
	%rsi: 7ffeefd2fed0
	%rdi: 7
	%orig_rax: ffffffffffffffff
	%rip: 400b4e
	%cs: 33
	%eflags: 293
	%rsp: 7ffeefd2ff08
	%ss: 2b
	%fs_base: 1ab8880
	%gs_base: 0
	%ds: 0
	%es: 0
	%fs: 0
	%gs: 0

	Please hit any key to continue: 

	Executable /home/zg/Documents/trace/getopt_demo/test (pid=24745) has hit breakpoint 0x400b4d
	%r15: 0
	%r14: 6b9018
	%r13: 0
	%r12: 401930
	%rbp: 7ffeefd2ff20
	%rbx: 400400
	%r11: 246
	%r10: 0
	%r9: 14
	%r8: 0
	%rax: 0
	%rcx: 448be1
	%rdx: 0
	%rsi: 7ffeefd2fed0
	%rdi: 7
	%orig_rax: ffffffffffffffff
	%rip: 400b4e
	%cs: 33
	%eflags: 293
	%rsp: 7ffeefd2ff08
	%ss: 2b
	%fs_base: 1ab8880
	%gs_base: 0
	%ds: 0
	%es: 0
	%fs: 0
	%gs: 0

	Please hit any key to continue: 

	Executable /home/zg/Documents/trace/getopt_demo/test (pid=24745) has hit breakpoint 0x400b4d
	%r15: 0
	%r14: 6b9018
	%r13: 0
	%r12: 401930
	%rbp: 7ffeefd2ff20
	%rbx: 400400
	%r11: 246
	%r10: 0
	%r9: 14
	%r8: 0
	%rax: 0
	%rcx: 448be1
	%rdx: 0
	%rsi: 7ffeefd2fed0
	%rdi: 7
	%orig_rax: ffffffffffffffff
	%rip: 400b4e
	%cs: 33
	%eflags: 297
	%rsp: 7ffeefd2ff08
	%ss: 2b
	%fs_base: 1ab8880
	%gs_base: 0
	%ds: 0
	%es: 0
	%fs: 0
	%gs: 0

	Please hit any key to continue: 

	Executable /home/zg/Documents/trace/getopt_demo/test (pid=24745) has hit breakpoint 0x400b4d
	%r15: 0
	%r14: 6b9018
	%r13: 0
	%r12: 401930
	%rbp: 7ffeefd2ff20
	%rbx: 400400
	%r11: 246
	%r10: 0
	%r9: 14
	%r8: 0
	%rax: 0
	%rcx: 448be1
	%rdx: 0
	%rsi: 7ffeefd2fed0
	%rdi: 7
	%orig_rax: ffffffffffffffff
	%rip: 400b4e
	%cs: 33
	%eflags: 246
	%rsp: 7ffeefd2ff08
	%ss: 2b
	%fs_base: 1ab8880
	%gs_base: 0
	%ds: 0
	%es: 0
	%fs: 0
	%gs: 0

	Please hit any key to continue: 

	Executable /home/zg/Documents/trace/getopt_demo/test (pid=24745) has hit breakpoint 0x400b4d
	%r15: 0
	%r14: 6b9018
	%r13: 0
	%r12: 401930
	%rbp: 7ffeefd2ff20
	%rbx: 400400
	%r11: 246
	%r10: 0
	%r9: 14
	%r8: 0
	%rax: 0
	%rcx: 448be1
	%rdx: 0
	%rsi: 7ffeefd2fed0
	%rdi: 4d
	%orig_rax: ffffffffffffffff
	%rip: 400b4e
	%cs: 33
	%eflags: 202
	%rsp: 7ffeefd2ff08
	%ss: 2b
	%fs_base: 1ab8880
	%gs_base: 0
	%ds: 0
	%es: 0
	%fs: 0
	%gs: 0

	Please hit any key to continue: 
	Completed tracing pid: 24745
	```
