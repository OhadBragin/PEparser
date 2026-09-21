#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>

#include "parser.h"	

PeType detect_pe_type(FILE* fp) {
	if (!fp) {
		return PE_TYPE_ERROR;
	}

	//save current pointer position
	long original_pos = ftell(fp);
	rewind(fp);

	//read magic number
	uint16_t e_magic = 0;
	if (fread(&e_magic, sizeof(uint16_t), 1, fp) != 1 || e_magic != 0x5A4D) {
		fseek(fp, original_pos, SEEK_SET);
		return PE_TYPE_UNKNOWN;
	}

	//get NT Header pos through pe_offset
	uint32_t pe_offset = 0;
	fseek(fp, 0x3c, SEEK_SET);
	if (fread(&pe_offset, sizeof(uint32_t), 1, fp) != 1) {
		fseek(fp, original_pos, SEEK_SET);
		return PE_TYPE_ERROR;
	}
	if ((uintmax_t)pe_offset + 0x5cU > (uintmax_t)LONG_MAX) {
		fseek(fp, original_pos, SEEK_SET);
		return PE_TYPE_ERROR;
	}
	long pe_header_offset = (long)pe_offset;

	//jump to PE signature
	fseek(fp, pe_header_offset, SEEK_SET);
	uint32_t pe_sig = 0;
	if (fread(&pe_sig, sizeof(uint32_t), 1, fp) != 1 || pe_sig != 0x00004550) {
		fseek(fp, original_pos, SEEK_SET);
		return PE_TYPE_ERROR;
	}

	//read characteristics
	fseek(fp, pe_header_offset + 0x16L, SEEK_SET);
	uint16_t characteristics = 0;
	if (fread(&characteristics, sizeof(uint16_t), 1, fp) != 1) {
		fseek(fp, original_pos, SEEK_SET);
		return PE_TYPE_ERROR;
	}
;

	// --- parse characteristics
	// must have bit 1 (IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002) set
	if (!(characteristics & 0x0002)) {
		fseek(fp, original_pos, SEEK_SET);
		return PE_TYPE_UNKNOWN;
	}

	//validate the Optional Header before reading its Subsystem field
	uint16_t optional_header_size = 0;
	fseek(fp, pe_header_offset + 0x14L, SEEK_SET);
	if (fread(&optional_header_size, sizeof(uint16_t), 1, fp) != 1) {
		fseek(fp, original_pos, SEEK_SET);
		return PE_TYPE_ERROR;
	}

	uint16_t optional_header_magic = 0;
	fseek(fp, pe_header_offset + 0x18L, SEEK_SET);
	if (fread(&optional_header_magic, sizeof(uint16_t), 1, fp) != 1) {
		fseek(fp, original_pos, SEEK_SET);
		return PE_TYPE_ERROR;
	}
	if (optional_header_size < 0x46 ||
		(optional_header_magic != 0x10b && optional_header_magic != 0x20b)) {
		fseek(fp, original_pos, SEEK_SET);
		return PE_TYPE_ERROR;
	}

	//read the Optional Header Subsystem field:
	uint16_t subsystem = 0;
	fseek(fp, pe_header_offset + 0x5cL, SEEK_SET);
	if (fread(&subsystem, sizeof(uint16_t), 1, fp) != 1) {
		fseek(fp, original_pos, SEEK_SET);
		return PE_TYPE_ERROR;
	}

	//restore position
	fseek(fp, original_pos, SEEK_SET);

	//kernel drivers have the IMAGE_FILE_SYSTEM bit (0x1000) set
	if (characteristics & 0x1000) {
		return PE_TYPE_SYS;
	}

	//native processes use IMAGE_SUBSYSTEM_NATIVE without the SYSTEM bit
	if (subsystem == 1) {
		return PE_TYPE_NATIVE;
	}

	//DLLs have bit 13 (IMAGE_FILE_DLL = 0x2000) set
	if (characteristics & 0x2000) {
		return PE_TYPE_DLL;
	}

	//otherwise its EXE
	return PE_TYPE_EXE;
}

//convert enum to string
const char* pe_type_to_string(PeType type) {
	switch (type) {
	case PE_TYPE_EXE:     return "Executable (.exe)";
	case PE_TYPE_DLL:     return "Dynamic Link Library (.dll)";
	case PE_TYPE_SYS:     return "Driver (.sys)";
	case PE_TYPE_NATIVE:  return "Native process";
	case PE_TYPE_UNKNOWN: return "Not a PE file / Unknown";
	case PE_TYPE_ERROR:   return "File I/O Error";
	default:              return "Invalid Type";
	}
}
