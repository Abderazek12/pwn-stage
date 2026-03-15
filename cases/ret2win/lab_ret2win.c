#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win() {
    puts("[+] win() appelée !");
    system("/bin/sh");
}

void vuln() {
    char buf[64];
    puts("Input:");
    read(0, buf, 300); // overflow volontaire
    puts("Bye");
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln();
    return 0;
}
