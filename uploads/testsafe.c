#include <stdio.h>
int main() {
    char buf[64];
    fgets(buf, sizeof(buf), stdin);
    printf("Entrée: %s", buf);
    return 0;
}
