// Based on MITRE's CWE-190, demonstrative example 2
// https://cwe.mitre.org/data/definitions/190.html

#include <stdio.h>
#include <stdlib.h>
#include "__fc_builtin.h"

/*@ ensures \result <= INT_MAX / sizeof(char*);
  @ assigns \result \from \nothing;
*/
int packet_get_int();

char* packet_get_string(char *arg) {
  return "";
}

int main(void) {
  int i, nresp;
  char **response;
  nresp = packet_get_int();
  if (nresp > 0) {
    response = malloc(nresp * (int) sizeof (char*));
    //@ admit \valid(response + (0..nresp-1)); // Since Eva loses the relation that response has size nresp * sizeof(char*)
    /*@ loop invariant 0 <= i <= nresp;
      @ loop invariant \valid(response + (0..nresp-1));
    */
    for (i = 0; i < nresp; i++) {
      response[i] = packet_get_string(NULL);
      //@ assert \valid(response + (0..nresp-1));
    }
  }
}
