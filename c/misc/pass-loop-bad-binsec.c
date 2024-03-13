#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define SIZE (1 << 4)
char arg[SIZE];
char pass[SIZE];
int n = SIZE;

int check(char *arg, char *pass)
{
  int i;
  for (i=0; i < n && arg[i]==pass[i]; i++);

  return (i==n);
}

int main(void) {
  exit(check(arg,pass));

}
