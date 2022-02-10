/*PLOVER: RACE.TOCTOU*/

/*
Description: A file is accessed multiple times by name in a publically accessible directory.  A race condition exists between the accesses where an attacker can replace the file referenced by the name.
Keywords: Size0 Complex0 Race Filename
*/

#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#define MYFILE	"/tmp/myfile"
#define	UID	100
#define	GID	100

void
test(char *str)
{
	int fd;

	fd = creat(MYFILE, 0644);
	if(fd == -1)
		return;
	if(fchown(fd, UID, GID) < 0)							/* FIX */
		;
	if(close(fd) < 0)
		;
}

int
main(int argc, char **argv)
{
	char *userstr;

	if(argc > 1) {
		userstr = argv[1];
		test(userstr);
	}
	return 0;
}

