#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// gcc -g -w -o pwn3 -fno-stack-protector -no-pie pwn3.c

void hammingDistance() {
    char a[256];
    char b[256];
    puts("Enter the first DNA sequence:");
    gets(&a);
    puts("Enter the second DNA sequence:");
    gets(&b);
    int x = compute(a, b);
    printf("The hamming distance between the two DNA sequences is: %d\n", x);
}

int compute(const char* a, const char* b) {
	int i = 0;
	while(*a && *b) {
		i += (*a++ != *b++);
	}
	return i;
}

void setup() {
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
}

int main(int argc, char **argv) {
    setup();
    hammingDistance();
    return 0;
}
