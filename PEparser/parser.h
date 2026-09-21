#pragma once

#include <stdio.h>

typedef enum {
    PE_TYPE_ERROR = -1,    // File couldnt be read or invalid handle
    PE_TYPE_UNKNOWN = 0,   // valid file but not PE
    PE_TYPE_EXE,           // .exe
    PE_TYPE_DLL,           // .dll
    PE_TYPE_SYS,           // .sys
    PE_TYPE_NATIVE         // native process
} PeType;

PeType detect_pe_type(FILE* fp);
const char* pe_type_to_string(PeType type);
