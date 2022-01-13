#include <stdlib.h>

int main() {
    void* block1 = malloc(12);
    void* block2 = malloc(12);
    
    free(block1);
    memcpy(block1, "AAAAAAAAAAAAAAAAAAAA", 20);
}
