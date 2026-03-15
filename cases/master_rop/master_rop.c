#include <stdio.h>
#include <stdlib.h>

void setup() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
}

// Fonction secrète qui nécessite des paramètres précis !
void win(unsigned int key1, unsigned int key2) {
    if (key1 == 0xDEADBEEF && key2 == 0xCAFEBABE) {
        printf("\n[+] MAGNIFIQUE ! ROP Chain validée. Arguments corrects.\n");
        printf("[+] Voici ton flag : PWN_STAGE{R0p_Ch41n_M4st3r_992}\n\n");
    } else {
        printf("\n[-] Arguments invalides... key1=0x%x, key2=0x%x\n", key1, key2);
        printf("[-] Essaie encore de forger ta ROP chain !\n\n");
    }
}

// Une petite fonction qui ne sert à rien à part nous donner des gadgets utiles
void gadget_farm() {
    asm("pop %rdi; ret;");
    asm("pop %rsi; ret;");
}

// Désactive le canary juste pour cette fonction pour le test
__attribute__((optimize("no-stack-protector")))
void vuln() {
    char buffer[32];
    printf("--- MASTER ROP CHALLENGE ---\n");
    printf("Objectif : Appeler win() avec 0xDEADBEEF et 0xCAFEBABE\n");
    printf("Prouvez que vous maîtrisez la pile. Entrée : ");
    gets(buffer); // <-- Faille ici
}

int main() {
    setup();
    vuln();
    return 0;
}
