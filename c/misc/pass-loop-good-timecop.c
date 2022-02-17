#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <valgrind/poison.h>

int check(char *arg, char *pass)
{
  poison(arg,5);  // secret argument of size 5 bytes
  poison(pass,5); // secret password of size 5 bytes
  int n = 5;
  int i,res=1;
  for (i=0; i < n; i++) {
    res &= arg[i] == pass[i];
  }
  return res;
}

int main(void) {
  check("abcdef","abcdef");
  check("abdcef","abcdef");
}
