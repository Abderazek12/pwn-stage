#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// Fonction cible à appeler via notre ROP chain
void win(long magic) {
    if (magic == 0xdeadbeef) {
        puts("ROP Chain Reussie ! Argument valide.");
        system("/bin/sh");
    } else {
        printf("Echec: Mauvais argument (0x%lx)\n", magic);
    }
}

// Fonction factice pour injecter des gadgets dans le binaire
void gadgets() {
    __asm__("pop %rdi; ret");
}

void vuln() {
    char buf[64];
    puts("Input:");
    // Vulnérabilité Buffer Overflow
    read(0, buf, 300);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln();
    return 0;
}
