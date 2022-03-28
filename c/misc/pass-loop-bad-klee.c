#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <klee/klee.h>

int check(char *arg, char *pass)
{
  klee_set_taint(1,arg,5);   // secret argument of size 5 bytes
  klee_set_taint(1,pass,5); // secret password of size 5 bytes
  int n = 5;
  int i;
  for (i=0; i < n && arg[i]==pass[i]; i++);

  return (i==n);
}

int main(void) {
  char arg[5];
  char pass[5];
  klee_make_symbolic(arg,5,"arg");
  arg[4]='\0';
  klee_make_symbolic(pass,5,"pass");
  pass[4]='\0';
  return check(arg,pass);

}
