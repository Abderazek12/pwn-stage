#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Fonction cachée (L'analyzer devrait trouver /bin/sh ici)
void secret_backdoor() {
    system("/bin/sh");
}

// Fonction vulnérable
void vuln() {
    char buffer[64];
    
    printf("--- WELCOME TO EXPERT ARENA ---\n");
    printf("1. Tape quelque chose pour inspecter la mémoire : ");
    
    // Faille 1 : L'analyzer va détecter read() et printf(variable)
    read(0, buffer, 63);
    printf(buffer); 
    
    printf("\n2. Maintenant, essaie de crasher le programme : ");
    
    // Faille 2 : L'analyzer va détecter gets()
    gets(buffer); 
}

int main() {
    // Désactive le buffering (L'analyzer va voir setvbuf dans la table PLT)
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    
    vuln();
    return 0;
}
