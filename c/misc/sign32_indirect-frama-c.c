
/*@ ensures \tainted(\result) <==> \tainted(x);
  @ assigns \result \from x;
*/ 
int get_sign(int x);

int main(int argc, char **argv)
{
    int a = 1000;
    //@ taint a;
    int s = get_sign(a);
    //@ assert !\tainted(s);
    
    return s;
}
