#include <stdio.h>
#include <stdbool.h>

int main (void)
{
	int i[10];
	int j = 0;

	while (j < sizeof i / sizeof i[0])		/* FIX */
	{
		i[j] = 5;
		++j;
	}

	for (j = 0; j < sizeof i / sizeof i[0]; ++j)
		printf("Value = %d\n", i[j]);

	return 0;
}
