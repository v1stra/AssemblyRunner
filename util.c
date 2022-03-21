#pragma once
#include "util.h"

BOOL string_get_args_by_name(const int argc, const char * argv[], const char * name, const char ** theArgs, const char * defaultValue)
{
	BOOL result = FALSE;
	const char * pArgName, * pSeparator;
	SIZE_T argLen, nameLen = strlen(name);
	int i;
	for(i = 0; i < argc; i++)
	{
		if((strlen(argv[i]) > 1) && ((argv[i][0] == '/') || (argv[i][0] == '-')))
		{
			pArgName = argv[i] + 1;
			if(!(pSeparator = strchr(argv[i], ':')))
				pSeparator = strchr(argv[i], '=');

			argLen =  (pSeparator) ? (pSeparator - pArgName) : strlen(pArgName);
			if((argLen == nameLen) && strncmp(name, pArgName, argLen) == 0)
			{
				if(theArgs)
				{
					if(pSeparator)
					{
						*theArgs = pSeparator + 1;
						result = *theArgs[0] != '\0';
					}
				}
				else
					result = TRUE;
				break;
			}
		}
	}
	if(!result && theArgs)
	{
		if(defaultValue)
		{
			*theArgs = defaultValue;
			result = TRUE;
		}
		else *theArgs = NULL;
	}
	return result;
}

BOOL string_bool_args_by_name(int argc, char * argv[], const char * name, PBOOL value) // TRUE when name exist (not value related)
{
	BOOL status = FALSE;
	char* szData = NULL;
	if(status = string_get_args_by_name(argc, argv, name, &szData, NULL))
	{
		if((strcmp(szData, "on") == 0) || (strcmp(szData, "true") == 0) || (strcmp(szData, "1") == 0))
			*value = TRUE;
		else if((strcmp(szData, "off") == 0) || (strcmp(szData, "false") == 0) || (strcmp(szData, "0") == 0))
			*value = FALSE;
		else printf("%s argument need on/true/1 or off/false/0\n", name);
	}
	return status;
}

BOOL file_exists(char * fileName)
{
	BOOL reussite = FALSE;
	HANDLE hFile = NULL;

	reussite = ((hFile = CreateFile(fileName, 0, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL)) && hFile != INVALID_HANDLE_VALUE);
	if(reussite)
		CloseHandle(hFile);
	return reussite;
}

BOOL file_read(char * fileName, PBYTE * data, PDWORD length, DWORD flags)
{
	BOOL reussite = FALSE;
	DWORD dwBytesReaded;
	LARGE_INTEGER filesize;
	HANDLE hFile = NULL;

	if((hFile = CreateFile(fileName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, flags, NULL)) && hFile != INVALID_HANDLE_VALUE)
	{
		if(GetFileSizeEx(hFile, &filesize) && !filesize.HighPart)
		{
			*length = filesize.LowPart;
			if(*data = (PBYTE) LocalAlloc(LPTR, *length))
			{
				if(!(reussite = ReadFile(hFile, *data, *length, &dwBytesReaded, NULL) && (*length == dwBytesReaded)))
					LocalFree(*data);
			}
		}
		CloseHandle(hFile);
	}
	return reussite;
}

BOOL file_write(char * fileName, PBYTE * data, DWORD length)
{
	BOOL reussite = FALSE;
	DWORD dwBytesWritten = 0;
	HANDLE hFile = NULL;

	if ((hFile = CreateFile(fileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL)) && hFile != INVALID_HANDLE_VALUE)
	{
		if (WriteFile(hFile, data, length, &dwBytesWritten, NULL) && (length == dwBytesWritten))
			reussite = FlushFileBuffers(hFile);
		CloseHandle(hFile);
	}
	return reussite;
}

BOOL bytes_xor(PBYTE data, DWORD length) {
	const char* key = "TESTKEY";
	int keylength = strlen(key);
	DWORD i;
	for (i = 0; i < length; i++) {
		data[i] ^= key[i % keylength];
	}
	return TRUE;
}