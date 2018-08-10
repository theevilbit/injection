#pragma once
#include <windows.h>
DWORD FindPIDByName(LPWSTR pName);

void ErrorExit(LPTSTR lpszFunction);

int GetFunctionAddressFromDll(PSTR pszDllName, PSTR pszFunctionName, PVOID *ppvFunctionAddress);

#define STATUS_SUCCESS 1
#define STATUS_FAIL -1