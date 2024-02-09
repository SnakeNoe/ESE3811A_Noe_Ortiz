// Tarea 4 - Noe Ortiz """

#include <stdio.h>
#include "sodium.h"

int main(void) {
    uint32_t random = 0;
    const int upperLimit = 2000;

    if (sodium_init() < 0) {
        printf("Initialization error!\n");
    }

    random = randombytes_random();
    printf("Random: %d\n", random);
    random = randombytes_uniform(upperLimit);
    printf("Random number with upper limit: %d\n", random);

    if (randombytes_close()) {
        printf("Erasing error!\n");
    }

    return 0;
}