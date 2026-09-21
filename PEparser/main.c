#include <stdio.h>
#include <stdlib.h>
#include "parser.h"


int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <binary_file>\n", argv[0]);
        return 1;
    }

    //open file
    FILE* fp = fopen(argv[1], "rb");
    if (!fp) {
        perror("Failed to open file");
        return 1;
    }

    PeType type = detect_pe_type(fp);
    fclose(fp);

    
    printf("Detected type: %s\n", pe_type_to_string(type));

    return 0;
}