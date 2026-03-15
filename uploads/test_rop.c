#include <stdio.h>
#include <unistd.h>

void gadget() {
    asm("pop %rdi; ret;");
}

int main() {
    char buf[40];
    puts("Payload:");
    read(0, buf, 400); // VULN: overflow
    puts("End");
    return 0;
}
