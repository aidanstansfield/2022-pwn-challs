#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// gcc -m32 -g -w -o pwn1 -fno-stack-protector -z execstack pwn1.c
// install libc6-i386 to get the 32 bit libraries necessary to run in 32 bit mode

void contains() {
    char haystack[128];
    char needle[64];
    printf("Enter the string to search within:\n");
    gets(&haystack);
    printf("Debug: the address of haystack is: %08x\n", haystack);
    printf("Enter the substring to search for:\n");
    gets(&needle);
    char* res = strstr(haystack, needle);
    if (res) {
      printf("Substring found at address: %08x\n", res);
      printf("Difference between the two addresses is: %d\n", res - haystack);
    } else {
      printf("Substring not found!\n");
    }
}

void setup() {
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
}

int main(int argc, char **argv) {
    setup();
    contains();
    printf("Exiting\n");
    return 0;
}