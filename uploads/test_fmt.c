#include <stdio.h>
#include <stdlib.h>

void win() {
    system("/bin/sh");
}

int main() {
    char buf[256];
    puts("Input:");
    fgets(buf, sizeof(buf), stdin);

    // VULN: format string (user controls format)
    printf(buf);

    puts("\nDone.");
    return 0;
}
