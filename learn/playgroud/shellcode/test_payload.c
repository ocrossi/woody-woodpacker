char code[] = "";

int main()
{
    int (*func)();
    func = (int(*)()) code;
    (int)(*func)();
    return 0;
}

