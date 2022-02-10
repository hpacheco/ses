/*
From "CLASP" 5.6.9.10

In this example, second_char is intended to point to the second byte of p. But, adding 1 to p actually adds sizeof(int) to p, giving a result that is incorrect (3 bytes off on 32-bit platforms). If the resulting memory address is read, this could potentially be an 
information leak.  If it is a write, it could be a security-criticial write to 
unauthorized memory - whether or not it is a buffer overflow. Note that the above code may also be wrong in other ways, particularly in a 
little endian environment.
*/

#include <stdio.h>

/*  Strings    "ABC"       "EFG"       "IJK"    */
int x[3] = {0x00434241, 0x00474645, 0x004B4A49};

int main()
{
	int *p = x;
	char * second_char = (char *)(p + 1);		/* FLAW */
	/* Expecting to print 'B' but it's actually 'E' that "second_char" is pointing to */
	printf ("%c\n", *second_char);
	return 0;
}
