#include <stdio.h>
#include <string.h>

int main() {
    char buf[32];
    printf("Entrée : ");
    if (fgets(buf, sizeof(buf), stdin) != NULL) {
        printf("Vous avez entré : %s", buf);
    }
    return 0;
}
