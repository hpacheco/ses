#include <stdio.h>

int main ()
{
	/* Using the value of an unitialized variable is not safe. */
	int foo = 0;									/* FIX */
	if (foo==0) printf("foo= 0");

	return 0;
}

