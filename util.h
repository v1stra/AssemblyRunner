#include "globals.h"

BOOL string_get_args_by_name(const int argc, const char * argv[], const char * name, const char ** theArgs, const char * defaultValue);

BOOL string_bool_args_by_name(int argc, char * argv[], const char * name, PBOOL value);

BOOL file_exists(char * fileName);

BOOL file_read(char * fileName, PBYTE * data, PDWORD length, DWORD flags);
