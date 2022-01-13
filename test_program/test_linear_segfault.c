#include <stdlib.h>
#include <stdio.h>

int main(int argc, char** argv) {
    char* filename = argv[1];
    FILE* file = fopen(filename, "r");
    const char* test_string = "HELLO\0WORLD\0GOODBYE\0"; 
    char line[256];

    void* line_ptr = fgets(line, sizeof(line), file);
    while(line_ptr) {
        int offset = *(int*) line_ptr;
        printf("offset: %d\n", offset);
        line_ptr = fgets(line, sizeof(line), file);
        printf("%s\n", test_string + offset);
    }
};
