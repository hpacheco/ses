#include <stdio.h>
#include <stdbool.h>

int main (void)
{
	int i[10];
	int j = 0;

	while (j < 10000)
	{
		i[j] = 5;				/* FLAW */
		++j;
	}

	for (j = 0; j < sizeof i / sizeof i[0]; ++j)
		printf("Value = %d\n", i[j]);

	return 0;
}
