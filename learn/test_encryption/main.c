#include <stdio.h>
#include <string.h>


extern void encrypt(const char *key, const char *text, size_t len);
extern void decrypt(const char *key, const char *text, size_t len);

int main() {
    char key[] = "ABCDEF";
    char text[] = "im not encrypted but i can calculate my own len\n";
    
    encrypt(key, text, strlen(text));
    printf("Encrypted text : \n");
    printf("%s\n", text);
    decrypt(key, text, strlen(text));
    printf("Decrypted text : \n");
    printf("%s\n", text);


    return 0;
}
