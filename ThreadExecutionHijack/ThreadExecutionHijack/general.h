#pragma once
#include <windows.h>
DWORD FindPIDByName(LPWSTR pName);

void ErrorExit(LPTSTR lpszFunction);

int GetFunctionAddressFromDll(PSTR pszDllName, PSTR pszFunctionName, PVOID *ppvFunctionAddress);
DWORD FindThreadInPID(DWORD pid);

void PutDwordIntoCharX86(SIZE_T address, unsigned char* sc, int position);
void PutDwordIntoCharX64(SIZE_T address, unsigned char* sc, int position);

#define STATUS_SUCCESS 1
#define STATUS_FAIL -1