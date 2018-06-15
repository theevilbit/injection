#include "stdafx.h"
#include <cstdio>
#include <windows.h>
#include <tlhelp32.h>
#include <strsafe.h>

#define STATUS_SUCCESS 1
#define STATUS_FAIL -1

//source: https://msdn.microsoft.com/en-us/library/windows/desktop/ms680582(v=vs.85).aspx
void ErrorExit(LPTSTR lpszFunction)
{
	// Retrieve the system error message for the last-error code
	LPVOID lpMsgBuf;
	DWORD dw = GetLastError();

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpMsgBuf,
		0, NULL);

	// Display the error message and exit the process
	wprintf(L"[-] %s failed with error 0x%x: %s", lpszFunction, dw, lpMsgBuf);

	LocalFree(lpMsgBuf);
	ExitProcess(dw);
}

DWORD FindPIDByName(LPWSTR pName)
{
	PROCESSENTRY32 pEntry;
	pEntry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if ((DWORD)snapshot < 1)
	{
		ErrorExit(TEXT("CreateToolhelp32Snapshot"));
	}
	if (Process32First(snapshot, &pEntry) == TRUE)
	{
		while (Process32Next(snapshot, &pEntry) == TRUE)
		{
			if (NULL != wcsstr(pEntry.szExeFile, pName))
			{
				return pEntry.th32ProcessID;
			}
		}
		ErrorExit(TEXT("Process32Next"));
	}
	else
	{
		ErrorExit(TEXT("Process32First"));
	}

	CloseHandle(snapshot);
	return 0;
}

int GetFunctionAddressFromDll(PSTR pszDllName, PSTR pszFunctionName, PVOID *ppvFunctionAddress)
{
	HMODULE hModule = NULL;
	PVOID	pvFunctionAddress = NULL;

	hModule = GetModuleHandleA(pszDllName);
	if (NULL == hModule)
	{
		ErrorExit(TEXT("GetModuleHandleA"));
	}

	pvFunctionAddress = GetProcAddress(hModule, pszFunctionName);
	if (NULL == pvFunctionAddress)
	{
		ErrorExit(TEXT("GetProcAddress"));
	}

	*ppvFunctionAddress = pvFunctionAddress;
	return STATUS_SUCCESS;
}

DWORD FindThreadInPID(DWORD pid)
{
	printf("[*] Finding a thread to hijack in the given process\r\n");
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		ErrorExit(TEXT("CreateToolhelp32Snapshot"));
	}

	HANDLE hThread;
	THREADENTRY32 te32;
	te32.dwSize = sizeof(te32);

	if (!Thread32First(hSnapshot, &te32))
	{
		ErrorExit(TEXT("Thread32First"));
	}

	BOOL found_thread = FALSE;
	while (Thread32Next(hSnapshot, &te32))
	{
		if (te32.th32OwnerProcessID == pid)
		{
			printf("[+] Found thread in target process\r\n");
			found_thread = TRUE;
			break;
		}
	}

	CloseHandle(hSnapshot);
	if (found_thread)
	{
		return te32.th32ThreadID;
	}
	else
	{
		printf("[-] Couldn't find thread, exiting...\r\n");
		ExitProcess(-1);
	}

}

void PutDwordIntoCharX86(SIZE_T address, unsigned char* sc, int position)
{
	BYTE b_1 = (address >> 24) & 0xff;
	BYTE b_2 = (address >> 16) & 0xff;
	BYTE b_3 = (address >> 8) & 0xff;
	BYTE b_4 = address & 0xff;

	sc[position] = b_4;
	sc[position + 1] = b_3;
	sc[position + 2] = b_2;
	sc[position + 3] = b_1;

	return;
}

void PutDwordIntoCharX64(SIZE_T address, unsigned char* sc, int position)
{
	BYTE b_1 = (address >> 56) & 0xff;
	BYTE b_2 = (address >> 48) & 0xff;
	BYTE b_3 = (address >> 40) & 0xff;
	BYTE b_4 = (address >> 32) & 0xff;
	BYTE b_5 = (address >> 24) & 0xff;
	BYTE b_6 = (address >> 16) & 0xff;
	BYTE b_7 = (address >> 8) & 0xff;
	BYTE b_8 = address & 0xff;

	sc[position] = b_8;
	sc[position + 1] = b_7;
	sc[position + 2] = b_6;
	sc[position + 3] = b_5;
	sc[position + 4] = b_4;
	sc[position + 5] = b_3;
	sc[position + 6] = b_2;
	sc[position + 7] = b_1;

	return;
}