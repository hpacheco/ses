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
#include <unistd.h>
#include <ctype.h>
#include <stdint.h>
#include "__fc_builtin.h"

/*@ ensures !\tainted(buff[0..buffLength-1]);
  @ assigns buff[0..buffLength-1] \from \old(buff[0..buffLength-1]), buffLength;
*/
void purify(char *buff,size_t buffLength);

int main(void) 
{
	char cat[] = "/bin/cat ";
	char arg[] = "evilarg";
	char *argv=arg;
	//@ taint argv[0..strlen(argv)];
	char command[30];
	size_t commandLength, catLength, argLength;

	catLength = strlen(cat);
	argLength = strlen(arg);
	if(argLength > SIZE_MAX / sizeof *command - catLength - 1)
	{
		printf("Parameter is too long\n");
		return -3;
	}
	commandLength = catLength + argLength + 1;
	if (command == NULL)
	{
		printf("Memory allocation problem");
		return -4;
	}
	strncpy(command, cat, catLength);
	strncpy(command + catLength, arg, commandLength - catLength);
	purify(command+catLength,commandLength-catLength);
	//@ admit command[commandLength-1] == '\0';
	//@ assert !\tainted(command[0..commandLength-1]);

	if (system(command) < 0)							
	{
		printf("Error running command %s\n", command);
		return -5;
	}

	return 0;
}
