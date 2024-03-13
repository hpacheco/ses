#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define SIZE (1 << 4)
char arg[SIZE];
char pass[SIZE];
int n = SIZE;

int check(char *arg, char *pass)
{
  int i,res=1;
  for (i=0; i < n; i++) {
    res &= arg[i] == pass[i];
  }

  return res;
}

int main(void) {
  exit(check(arg,pass));

}
