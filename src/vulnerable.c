#include <stdio.h>

/*
 * Demonstration of CWE-120: Buffer Copy without Checking Size of Input.
 * Note: gets() was officially deprecated in C99 and removed in C11 due to its inherent insecurity.
 */
void vulnerable_function(void) {
    char buffer[64];

    printf("Buffer allocated at: %p (size: 64 bytes)\n", (void*)buffer);
    printf("Enter input: ");

    // Vulnerable: gets() reads unbounded input from stdin into buffer
    gets(buffer);

    printf("Received input: %s\n", buffer);
}

int main(void) {
    vulnerable_function();
    return 0;
}
