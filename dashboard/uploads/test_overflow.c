#include <stdio.h>

int main() {
    char buf[32];
    printf("Entrée : ");
    gets(buf); // VULNÉRABLE
    printf("Vous avez entré : %s\n", buf);
    return 0;
}
