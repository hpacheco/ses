// Based on MITRE's CWE-190, demonstrative example 2
// https://cwe.mitre.org/data/definitions/190.html

#include <stdio.h>
#include <stdlib.h>
#include "__fc_builtin.h"

int packet_get_int() {
  return Frama_C_interval(1,80);
}

char* packet_get_string(char *arg) {
  return "";
}

int main(void) {
  int i, nresp;
  char **response;
  nresp = packet_get_int();
  //@ split nresp;
  if (nresp > 0) {
    //@ eva_allocate fresh;
    response = malloc(nresp * (int) sizeof (char*));
    for (i = 0; i < nresp; i++) {
      response[i] = packet_get_string(NULL);
    }
  }
  //@ merge nresp;
}
