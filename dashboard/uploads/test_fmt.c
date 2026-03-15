#include <stdio.h>

int main() {
    char user[64];
    printf("Entrée : ");
    fgets(user, sizeof(user), stdin);
    printf(user); // VULNÉRABLE aux injections format string
    return 0;
}
