#include <stdio.h>
#include <valgrind/taintgrind.h>

int get_sign(int x) {
    if (x == 0) return 0;
    if (x < 0)  return -1;
    return 1;
}
int main(int argc, char **argv)
{
    int a = 1000;
    // Defines int a as tainted
    TNT_TAINT(&a,sizeof(a));
    int s = get_sign(a);
    unsigned int t;
    TNT_IS_TAINTED(t,&s,sizeof(s));
    printf("%08x\n",t);
    return s;
}
