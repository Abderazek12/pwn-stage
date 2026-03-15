#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win() {
    printf("\n[+] PWNED !!! Le flux d'execution a ete detourne.\n");
    system("/bin/sh");
}

int main() {
    char buffer[64];
    setvbuf(stdout, NULL, _IONBF, 0); 
    setvbuf(stdin, NULL, _IONBF, 0);
    
    printf("--- PWN STAGE : TEST REEL ---\n");
    printf("Entrez le payload : ");
    gets(buffer); // La faille est ici
    
    return 0;
}
