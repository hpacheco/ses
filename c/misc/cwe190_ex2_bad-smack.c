// Based on MITRE's CWE-190, demonstrative example 2
// https://cwe.mitre.org/data/definitions/190.html

#include <stdio.h>
#include <stdlib.h>
#include "smack.h"
#include "assert.h"

int packet_get_int() {
  return __VERIFIER_nondet_int();
}

char* packet_get_string(char *arg) {
  return "";
}

int main(void) {
  int i, nresp;
  char **response;
  nresp = packet_get_int();
  if (nresp > 0) {
    response = malloc(nresp * (int) sizeof (char*));
    for (i = 0; i < nresp; i++) {
      response[i] = packet_get_string(NULL);
    }
  }
}