#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void secret() {
    system("/bin/sh");
}

void vuln() {
    char buf[128];
    printf("Input: ");
    read(0, buf, 256);
    printf(buf);   // vulnérabilité format string ici !
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln();
}
