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

static int __argc;

/*@ ensures 1 <= \result;
  @ ensures \result == _argc;
  @ assigns \result \from \nothing;
*/
extern int get_argc();

//// @ ensures \valid_read(\result + (0 .. argc-1));
////@ ensures \forall int i; 0 <= i < argc ==> valid_read_string(\result[i]);

/*@ ensures \valid_read(\result+0);
  @ ensures \valid_read(\result+1);
  @ ensures valid_read_string(\result[0]);
  @ ensures valid_read_string(\result[1]);
  @ assigns \result \from \nothing;
*/
extern char** get_argv(int argc);

int main(void) 
{
	int argc = get_argc();
	char** argv = get_argv(argc);
	//* //@ taint argv[1];
	char cat[] = "/bin/cat ";
	char *command;
	size_t commandLength, catLength, argLength;

	if (argc <= 1)
	{
		printf("No Command entered\n");
		return -1;
	}
	//@ assert 0;
	//@ assert 2 <= argc;
	
	// //@ assert \valid_read(argv + 0);
	// //@ assert \valid_read(argv + 1);
	//@ assert \valid_read(argv[0]);
	//@ assert \valid_read(argv[1]);
	//@ assert valid_read_string(argv[0]);
	//@ assert valid_read_string(argv[1]);
	//@ assert valid_read_string(argv[1]);

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
	///* /@ assert \tainted(command);

	if (system(command) < 0)							
	{
		printf("Error running command %s\n", command);
		free(command); 
		return -5;
	}

	free(command); 

	return 0;
}
