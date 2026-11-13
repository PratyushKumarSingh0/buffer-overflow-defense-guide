#include <stdio.h>

#define BUFFER_SIZE 64

/*
 * Remediated implementation: Enforces explicit buffer boundaries using fgets().
 */
void safe_function(void) {
    char buffer[BUFFER_SIZE];

    printf("Buffer allocated at: %p (size: %zu bytes)\n", (void*)buffer, sizeof(buffer));
    printf("Enter input: ");

    // Secure: fgets() reads at most sizeof(buffer) - 1 characters and guarantees null-termination
    if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
        printf("Received input: %s", buffer);
    } else {
        perror("Error reading input");
    }
}

int main(void) {
    safe_function();
    return 0;
}
