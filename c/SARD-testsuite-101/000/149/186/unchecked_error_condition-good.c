/* This software was developed at the National Institute of Standards and
 * Technology by employees of the Federal Government in the course of their
 * official duties. Pursuant to title 17 Section 105 of the United States
 * Code this software is not subject to copyright protection and is in the
 * public domain. NIST assumes no responsibility whatsoever for its use by
 * other parties, and makes no guarantees, expressed or implied, about its
 * quality, reliability, or any other characteristic.

 * We would appreciate acknowledgement if the software is used.
 * The SAMATE project website is: http://samate.nist.gov
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
	unsigned int i=0,j=0;
	unsigned int result = 0;
	printf("Enter two numbers:\n");
	result = scanf("%d %d", &i, &j);
	if (result != 2) {								/* FIX */
		printf ("Error, you should enter two numbers!\n");	
		return 1;
	}		
	printf ("Result = %d\n", i / j);
	return 0;
}
