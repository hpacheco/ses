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

#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <pwd.h>
#include <unistd.h>
#include <string.h>
#include <termios.h>
#include <security/pam_appl.h>
#include <stdint.h>

static uid_t userID = 1;


/* Replacement to memset() that cannot be optimized out */
char *my_memset_s(void *s, int c, size_t n)
{
	volatile uint8_t *p = (uint8_t *)s;
	while (n--)
		*p++ = c;

	return s;
}

/* Reads a password from a terminal - replaces obsolete getpass() function */
char * getpass_r(const char *prompt)
{
	struct termios oflags, nflags;
	char password[64] = { '\0' };
	char * ret = NULL;

	/* Disabling echo */
	if(tcgetattr(fileno(stdin), &oflags))
		return NULL;

	nflags = oflags;
	nflags.c_lflag &= ~ECHO;
	nflags.c_lflag |= ECHONL;

	if (tcsetattr(fileno(stdin), TCSAFLUSH, &nflags))
		return NULL;

	/* Read the password */
	fprintf(stderr, "%s", prompt);
	ret = fgets(password, sizeof(password), stdin);

	/* Restore echo */
	if (tcsetattr(fileno(stdin), TCSAFLUSH, &oflags))
	{
		my_memset_s(password, 0, sizeof(password));
		return NULL;
	}

	if(ret)
	{
		strtok(password, "\n");
		ret = strdup(password);
		my_memset_s(password, 0, sizeof(password));
	}

	return ret;
}


/* Conversation function used by the PAM authentication system */
int pam_conv_func(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr)
{
	int i, j;

	if (0 >= num_msg && num_msg > PAM_MAX_NUM_MSG)
		return PAM_CONV_ERR;

	*resp = calloc(num_msg, sizeof **resp);
	if(!*resp)
		return PAM_BUF_ERR;

	for (i = 0; i < num_msg; ++i)
	{
		switch (msg[i]->msg_style)
		{
			case PAM_PROMPT_ECHO_OFF:
			case PAM_PROMPT_ECHO_ON:
				fprintf(stderr, "Username: %s\n", (const char *)appdata_ptr);
				(*resp)[i].resp = getpass_r(msg[i]->msg);
				if ((*resp)[i].resp == NULL)
				{
					for (j = 0; j < num_msg; ++j)
						if ((*resp)[j].resp != NULL)
						{
							my_memset_s((*resp)[j].resp, 0, strlen((*resp)[j].resp));
		 					free((*resp)[j].resp);
						}
					my_memset_s(*resp, 0, num_msg * sizeof **resp);
					*resp = NULL;
					return PAM_CONV_ERR;
				}
				break;
			case PAM_ERROR_MSG:
				fputs(msg[i]->msg, stderr);
				break;
			case PAM_TEXT_INFO:
				fputs(msg[i]->msg, stdout);
				break;
			default:
				break;
		}
	}

	return PAM_SUCCESS;
}


int main(int argc, char *argv[])
{
	unsigned int u;
	int ret;
	pam_handle_t *pamh;
	struct pam_conv conv = { pam_conv_func, NULL } ;

	struct
	{
		char *name;
		uid_t uid;
		char *salt;
		char *hash;
	} users[2];

	users[0].name = "mark";
	users[1].name = "mel";

	for (u = 0; u < sizeof(users) / sizeof(*users); ++u)
	{
		conv.appdata_ptr = users[u].name;
		ret = pam_start("testcase149116", users[u].name, &conv, &pamh);
		if(ret != PAM_SUCCESS)
			continue;

		ret = pam_authenticate(pamh, 0);					/* FIX */
		if (ret == PAM_SUCCESS)
		{
			userID = users[u].uid;
			printf("Logged in\nWelcome %s!\n", users[u].name);
			break;
		}

		if(pam_end(pamh , ret) != PAM_SUCCESS)
			return -1;
	}

	return 0;
}
