#include <stdio.h>
#include <stdlib.h>

// La fonction secrète qu'on veut appeler
void win() {
    printf("Bravo, tu as pwn le binaire !\n");
    system("/bin/sh");
}

void vuln() {
    char buffer[64];
    printf("Entrez votre nom : ");
    gets(buffer); // <-- Faille très connue (Stack Overflow)
    printf("Bonjour %s\n", buffer);
}

int main() {
    vuln();
    return 0;
}
