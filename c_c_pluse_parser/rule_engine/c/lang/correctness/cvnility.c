#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <number>\n", argv[0]);
        return 1;
    }

    // ruleid: unsafe-atoi
    int value = atoi(argv[1]);  // ❌ No error handling or bounds checking

    if (value < 0) {
        printf("Negative numbers not allowed!\n");
        return 1;
    }

    printf("You entered: %d\n", value);
    return 0;
}
