
int get_sign(int x) {
    if (x == 0) return 0;
    if (x < 0)  return -1;
    return 1;
}

int main(int argc, char **argv)
{
    int a = 1000;
    //@ taint a;
    int s = get_sign(a);
    //@ assert !\tainted(s);
    
    return s;
}
