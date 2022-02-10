/*
From "CLASP" 5.6.9.10
*/

#include <stdio.h>

/*  Strings    "ABC"       "EFG"       "IJK"    */
int x[3] = {0x00434241, 0x00474645, 0x004B4A49};

int main()
{
	int *p = x;
	char * second_char = (char *)p + 1;		/* FIX */
	/* print 'B'  s expected */
	printf ("%c\n", *second_char);
	return 0;
}
