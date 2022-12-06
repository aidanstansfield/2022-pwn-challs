#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// gcc -m32 -g -w -o pwn0 -no-pie -fno-stack-protector pwn0.c
// install libc6-i386 to get the 32 bit libraries necessary to run in 32 bit mode

void debug() {
    system("/bin/sh");
}

char *strrev(char *str) {
    char *p1, *p2;
    if (! str || ! *str)
        return str;
    for (p1 = str, p2 = str + strlen(str) - 1; p2 > p1; ++p1, --p2) {
        *p1 ^= *p2;
        *p2 ^= *p1;
        *p1 ^= *p2;
    }
    return str;
}

void reverse() {
    char buffer[128];
    printf("Enter the string to reverse:\n");
    gets(&buffer);
    strrev(buffer);
    printf("%s\n", buffer);
}

void setup() {
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
}

int main(int argc, char **argv) {
    setup();
    reverse();
    printf("Exiting\n");
    return 0;
}