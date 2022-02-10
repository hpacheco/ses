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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <ctype.h>


const char cmd[] = "/bin/cat ";


/*
	One of the most basic filtering, remove the ';'

	SAMATE Edit: replaced by whitelisting to prevent command injection based on other operators like "&&"
*/
void purify(char *__buff)
{
	char buf[BUFSIZ] = "";
	char *c, *b = buf;

	for (c = __buff; *c != '\0'; c++)
	{
		if(isalnum(*c) || *c == '/' || *c == '_' || *c == '.')
			*b++ = *c;
	}
	*b = '\0';
	strcpy(__buff, buf);
}

int main(int argc, char *argv[])
{
	unsigned i;
	char buff[BUFSIZ];
	char sys[BUFSIZ] = "";

	if (fgets(buff, sizeof(buff) - sizeof(cmd), stdin))
	{
		strcat(sys, cmd);
		strcat(sys, buff);
		purify(sys + strlen(cmd));						/* FIX */
		for (i = 0; i < 5; ++i)
		{
			if (system(sys) < 0)
				fprintf(stderr, "Error running command %s\n", sys);
		}
	}

	return 0;
}
