#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

// gcc -m64 -g -w -o pwn-1 -fno-stack-protector -no-pie pwn-1.c

void vuln() {
    printf("Uh oh I forgot to check my bounds! Here's a shell for your troubles\n");
    system("/bin/sh");
    exit(0);
}

void setup() {
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
}

int main(int argc, char **argv) {
    setup();
    char buffer[64];
    signal(SIGSEGV, vuln);
    printf("What is your name?\n");
    scanf("%s", &buffer);
    printf("Hello %s!\n", buffer);
    return 0;
}
