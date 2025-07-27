#pragma once
#include <stdint.h>
void* get_shellcode_main(int is_x64, int* osize);
void* get_shellcode_aplib(int is_x64, int* osize);
void* get_shellcode_ntdll(int is_x64, int* osize);
TCHAR* dll_to_shellcode(CStringA in_file, CStringA out_fileA);
 int dll_to_shellcode(uint8_t shellcode_mode, char* param, CStringA in_file, CStringA out_file);
 byte* dll_to_shellcode(byte* fileBuf, int inFileSize,int* size_out);