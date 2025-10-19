#include <unistd.h>
#include <string.h>


int main() {
    char *txt = "hello payload\n";
    write(1, txt, strlen(txt));
}
