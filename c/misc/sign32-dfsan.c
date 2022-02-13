#include <sanitizer/dfsan_interface.h>
#include <assert.h>

int get_sign(int x) {
    if (x == 0) return 0;
    if (x < 0)  return -1;
    return 1;
}
int main(int argc, char **argv)
{
    int a = 1000;
    dfsan_label a_label = 1;
    dfsan_set_label(a_label, &a, sizeof(a));
    
    int s = get_sign(a);
    
    dfsan_label s_label = dfsan_get_label(s);
    assert(dfsan_has_label(s_label, a_label));
    
    return s;
}
