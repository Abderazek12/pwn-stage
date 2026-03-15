#include <stdio.h>
#include <stdlib.h>
void vuln() {
    char buf[64];
    gets(buf);
}
int main() {
    vuln();
    return 0;
}
