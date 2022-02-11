
# Lab 1 - Low-level security

One of the most common source vulnerabilities, even to this day, remains to be related to exploits for low-level programming languages such as C or C++. For instance, many of the [2021 Top 25 CWEs](https://cwe.mitre.org/top25/archive/2021/2021_cwe_top25.html) are due to memory violations, type violations or undefined behavior in C.

Instead of focusing on exploitation and mitigation, we will study how various existing analysis tools can support developers in detecting and fixing vulnerabilities.

In this lab we will see use a series of C examples that are part of the [SARD test suite](https://samate.nist.gov/SRD/testsuite.php#sardsuites). Each example comes as a pair of C programs where the first has a flaw and the second demonstrates how to possibly fix the flaw.

## Dynamic memory analysis

### Valgrind

Valgrind is an instrumentation framework for building dynamic analysis tools that works as an interpreter for compiled binaries, without the need to recompile the program or have access to the source code. Much like GDB, it can be used as a low-level debugger; since it instruments the original program at runtime, it may introduce a 20x-50x slowdown in program execution.

One of the most prominent Valgrind tools is the Memcheck memory error detector, which can find uses of freed or invalid memory, memory leaks, or uses of uninitialized memory. A detailed error list can be found in the [manual](https://valgrind.org/docs/manual/mc-manual.html#mc-manual.bugs).

#### Memory error - [buffer overflow](https://owasp.org/www-community/vulnerabilities/Buffer_Overflow)

Consider a simple [scpy7-bad.c](c/SARD-testsuite-100/000/149/079/scpy7-bad.c) vulnerable C program found:

```C
#define	MAXSIZE		40
void
test(char *str)
{
	char *buf;

	buf = malloc(MAXSIZE);
	if(!buf)
		return;
	strcpy(buf, str);				/* FLAW */
	printf("result: %s\n", buf);
	free(buf);
}
```

This program allocates 40 bytes of heap memory for a buffer, to which it comes some input `str`. There is a likely heap buffer overflow vulnerability, if the size of `str` is larger than 40 (the size of `buf`), which may lead to an exploit.
If we compile and run this program with a slightly larger input, however:
```ShellSession
$ gcc scpy7-bad.c
$ /a.out aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa             
result: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```
the program does not crash although `strcpy` is writing past the buffer.

We can analyze the same program execution with `valgrind` and obtain indicative errors that `strcpy`is performing invalid writes:

<details>
```ShellSession
$ valgrind ./a.out aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa         
==57008== Memcheck, a memory error detector
==57008== Copyright (C) 2002-2017, and GNU GPL'd, by Julian Seward et al.
==57008== Using Valgrind-3.18.1 and LibVEX; rerun with -h for copyright info
==57008== Command: ./a.out aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
==57008== 
==57008== Invalid write of size 1
==57008==    at 0x4855440: strcpy (vg_replace_strmem.c:553)
==57008==    by 0x108883: test (in /home/parallels/Desktop/SARD-testsuite-100/000/149/079/a.out)
==57008==    by 0x1088DB: main (in /home/parallels/Desktop/SARD-testsuite-100/000/149/079/a.out)
==57008==  Address 0x49ff068 is 0 bytes after a block of size 40 alloc'd
==57008==    at 0x484F0C8: malloc (vg_replace_malloc.c:381)
==57008==    by 0x108867: test (in /home/parallels/Desktop/SARD-testsuite-100/000/149/079/a.out)
==57008==    by 0x1088DB: main (in /home/parallels/Desktop/SARD-testsuite-100/000/149/079/a.out)
...
result: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
==57008== 
==57008== HEAP SUMMARY:
==57008==     in use at exit: 0 bytes in 0 blocks
==57008==   total heap usage: 2 allocs, 2 frees, 1,064 bytes allocated
==57008== 
==57008== All heap blocks were freed -- no leaks are possible
==57008== 
==57008== For lists of detected and suppressed errors, rerun with: -s
==57008== ERROR SUMMARY: 9 errors from 6 contexts (suppressed: 0 from 0)
```
<details>

#### [Memory leak](https://owasp.org/www-community/vulnerabilities/Memory_leak)

Consider a simple program [memory_leak_basic-bad.c](c/SARD-testsuite-100/000/149/189/memory_leak_basic-bad.c).

```C
int main(int argc, char *argv[])
{
	double *buff = (double *)NULL;
	buff = malloc(10 * sizeof(double));
	if (buff == (double *)NULL)
	{
		printf ("Allocation Error: Cannot allocate buff.\n");
		exit(0);		
	}
	// do something	
	buff = NULL;                                        /* FLAW */
	return 0;
}
```

This program has a memory leak, since the buffer `buff` is not freed after before the variable is reassigned.
Although this vulnerability does not affect the behavior of the program, it may clause a program to crash or run too slow due to excessive memory consumption. Valgrind will detect this leak:

```ShellSession
$ valgrind ./a.out                                                     
==57431== Memcheck, a memory error detector
==57431== Copyright (C) 2002-2017, and GNU GPL'd, by Julian Seward et al.
==57431== Using Valgrind-3.18.1 and LibVEX; rerun with -h for copyright info
==57431== Command: ./a.out
==57431== 
==57431== 
==57431== HEAP SUMMARY:
==57431==     in use at exit: 80 bytes in 1 blocks
==57431==   total heap usage: 1 allocs, 0 frees, 80 bytes allocated
==57431== 
==57431== LEAK SUMMARY:
==57431==    definitely lost: 80 bytes in 1 blocks
==57431==    indirectly lost: 0 bytes in 0 blocks
==57431==      possibly lost: 0 bytes in 0 blocks
==57431==    still reachable: 0 bytes in 0 blocks
==57431==         suppressed: 0 bytes in 0 blocks
==57431== Rerun with --leak-check=full to see details of leaked memory
==57431== 
==57431== For lists of detected and suppressed errors, rerun with: -s
==57431== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
```

#### [Use-after-free](https://owasp.org/www-community/vulnerabilities/Using_freed_memory)

Consider a simple program [useafterfree-bad.c](c/SARD-testsuite-100/000/149/219/useafterfree-bad.c) that allocates some memory but uses the variable after being freed:

```C
int main(){
      char * x = (char *) malloc(4);
      if (x == NULL)
        {printf("Memory allocation problem"); return 1;}
      free(x);
      if(x) *x = 'a';									/* FLAW */
      return 0;
}
```
This vulnerability will often cause the program to crash, and, if the freed memory gets reused, an attacker may control `x` similarly to a buffer overflow attack.
Valgrind will also detect this error: 

```ShellSession
$ valgrind ./a.out                                                    
==57317== Memcheck, a memory error detector
==57317== Copyright (C) 2002-2017, and GNU GPL'd, by Julian Seward et al.
==57317== Using Valgrind-3.18.1 and LibVEX; rerun with -h for copyright info
==57317== Command: ./a.out
==57317== 
==57317== Invalid write of size 1
==57317==    at 0x108864: main (in /home/parallels/Desktop/SARD-testsuite-100/000/149/219/a.out)
==57317==  Address 0x49ff040 is 0 bytes inside a block of size 4 free'd
==57317==    at 0x4851B40: free (vg_replace_malloc.c:872)
==57317==    by 0x10884F: main (in /home/parallels/Desktop/SARD-testsuite-100/000/149/219/a.out)
==57317==  Block was alloc'd at
==57317==    at 0x484F0C8: malloc (vg_replace_malloc.c:381)
==57317==    by 0x108823: main (in /home/parallels/Desktop/SARD-testsuite-100/000/149/219/a.out)
==57317== 
==57317== 
==57317== HEAP SUMMARY:
==57317==     in use at exit: 0 bytes in 0 blocks
==57317==   total heap usage: 1 allocs, 1 frees, 4 bytes allocated
==57317== 
==57317== All heap blocks were freed -- no leaks are possible
==57317== 
==57317== For lists of detected and suppressed errors, rerun with: -s
==57317== ERROR SUMMARY: 1 errors from 1 contexts (suppressed: 0 from 0)
```




