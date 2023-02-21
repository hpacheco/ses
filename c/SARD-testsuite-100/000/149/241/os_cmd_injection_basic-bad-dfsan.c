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
#include <sanitizer/dfsan_interface.h>

int main(int argc, char **argv) 
{
	printf("tainting first %d bytes of argv[1] %s\n",8,argv[1]);
	dfsan_label argv1_label = 1;
	dfsan_set_label(argv1_label,argv[1],8);
	char cat[] = "/bin/cat ";
	char *command;
	size_t commandLength, catLength, argLength;

	if (argc <= 1)
	{
		printf("No Command entered\n");
		return -1;
	}

	catLength = strlen(cat);
	argLength = strlen(argv[1]);
	if(argLength > SIZE_MAX / sizeof *command - catLength - 1)
	{
		printf("Parameter is too long\n");
		return -3;
	}
	commandLength = catLength + argLength + 1;
	command = (char *) malloc(commandLength * sizeof *command);
	if (command == NULL)
	{
		printf("Memory allocation problem");
		return -4;
	}

	strncpy(command, cat, catLength);
	strncpy(command + catLength, argv[1], commandLength - catLength);
	
	dfsan_label command_label;
	printf("checking taint for %d bytes of command (in 8-byte blocks)\n",commandLength);
	for (int i=0; i < commandLength; ) {
	  command_label = dfsan_read_label(command+i,8);
	  printf("%u ",command_label);
	  i+=8;
	}

	if (system(command) < 0)							/* FLAW */
	{
		printf("Error running command %s\n", command);
		free(command); 
		return -5;
	}

	free(command); 

	return 0;
}
