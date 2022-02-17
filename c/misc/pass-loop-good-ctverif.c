#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <smack.h>
#include "ctverif.h"

int check(char *arg, char *pass)
{
  public_in(__SMACK_value(arg));     // pointer value is public
  public_in(__SMACK_value(pass));    // pointer value is public
  public_in(__SMACK_values(arg,5));  // size of array is public and =5
  public_in(__SMACK_values(pass,5)); // size of array is public and =5
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
