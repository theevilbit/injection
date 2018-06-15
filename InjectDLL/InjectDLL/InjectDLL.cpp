// InjectDLL.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "general.h"
#include <psapi.h>
#include <stdio.h>
#include <Windows.h>


typedef DWORD(WINAPI *prototype_NtCreateThreadEx)(
	PHANDLE                 ThreadHandle,
	ACCESS_MASK             DesiredAccess,
	LPVOID                  ObjectAttributes,
	HANDLE                  ProcessHandle,
	LPTHREAD_START_ROUTINE  lpStartAddress,
	LPVOID                  lpParameter,
	BOOL                    CreateSuspended,
	DWORD                   dwStackSize,
	DWORD                   Unknown1,
	DWORD                   Unknown2,
	LPVOID                  Unknown3
	);

typedef DWORD(WINAPI *prototype_RtlCreateUserThread)(
	HANDLE      ProcessHandle,
	PSECURITY_DESCRIPTOR  SecurityDescriptor,
	BOOL      CreateSuspended,
	ULONG     StackZeroBits,
	PULONG     StackReserved,
	PULONG     StackCommit,
	LPVOID     StartAddress,
	LPVOID     StartParameter,
	HANDLE      ThreadHandle,
	LPVOID     ClientID
	);


int wmain(int argc, wchar_t**argv) //to read in arguments as unicode
{
	if (argc != 4)
	{
		printf("Usage: injectdll.exe [process name] [dll path] [option number]\noption 1 - CreateRemoteThread\noption 2 - NtCreateThreadEx\noption 3 - RtlCreateUserThread\n");
		return -1;
	}

	int option = _wtoi(argv[3]);
	if (option != 1 && option != 2 && option != 3)
	{
		printf("[-] Wrong option number\n");
		ExitProcess(-1);
	}

	//find the process ID by name
	DWORD pid = FindPIDByName(argv[1]);
	printf("[+] PID is: %d,0x%x\n" , (UINT)pid, (UINT)pid);

	//open process with all access
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL)
	{
		//printf("[-] Couldn't open process, exiting...\n");
		//return -1;
		ErrorExit(TEXT("OpenProcess"));
	}
	printf("[+] Process handle: 0x%x\n", (UINT)hProcess);

	
	//find the address of LoadLibrary (it's the same accross all processes)
	HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");
	if (hKernel32 == NULL)
	{
		ErrorExit(TEXT("GetModuleHandle"));
	}
	LPVOID llBaseAddress = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryW");
	if (llBaseAddress == NULL)
	{
		ErrorExit(TEXT("GetProcAddress"));
	}
	printf("[+] LoadLibrary base address is: 0x%x\n", (UINT)llBaseAddress);

	//allocate memory in target process
	LPVOID lpBaseAddress = (LPVOID)VirtualAllocEx(hProcess, NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (lpBaseAddress == NULL)
	{
		ErrorExit(TEXT("VirtualAllocEx"));
	}
	printf("[+] Allocated memory address in target process is: 0x%x\n", (UINT)lpBaseAddress);


	//write DLL name to target process
	SIZE_T *lpNumberOfBytesWritten = 0;
	BOOL resWPM = WriteProcessMemory(hProcess, lpBaseAddress, argv[2], wcslen(argv[2]) * 2, lpNumberOfBytesWritten);
	if (!resWPM)
	{
		ErrorExit(TEXT("WriteProcessMemory"));
	}
	printf("[+] DLL name is written to memory of target process\n");


	//start remote thread in target process
	HANDLE hThread = NULL;
	DWORD ThreadId = 0;

	switch (option)
	{
		//option 1: CreateRemoteThread
		case 1:
		{
			hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)llBaseAddress, lpBaseAddress, 0, (LPDWORD)(&ThreadId));
			if (hThread == NULL)
			{
				ErrorExit(TEXT("CreateRemoteThread"));
			}
			break;
		}
		//option 2: NtCreateThreadEx
		case 2:
		{
			prototype_NtCreateThreadEx pfnNtCreateThreadEx = NULL;
			PVOID pvEncodedPtr = NULL;
			GetFunctionAddressFromDll("ntdll.dll", "NtCreateThreadEx", (PVOID *)&pfnNtCreateThreadEx);

			pfnNtCreateThreadEx(&hThread, GENERIC_ALL, NULL, hProcess, (LPTHREAD_START_ROUTINE)llBaseAddress, lpBaseAddress, FALSE, NULL, NULL, NULL, NULL);
			if (hThread == NULL)
			{
				ErrorExit(TEXT("NtCreateThreadEx"));
			}	
			break;
		}
		//option 3: RtlCreateUserThread
		case 3:
		{
			prototype_RtlCreateUserThread pfnRtlCreateUserThread = NULL;
			PVOID pvEncodedPtr = NULL;
			GetFunctionAddressFromDll("ntdll.dll", "RtlCreateUserThread", (PVOID *)&pfnRtlCreateUserThread);

			pfnRtlCreateUserThread(hProcess, NULL, 0, 0, 0, 0, llBaseAddress, lpBaseAddress, &hThread, NULL);
			if (hThread == NULL)
			{
				ErrorExit(TEXT("RtlCreateUserThread"));
			}
			break;
		}
	}

	printf("[+] Successfully started DLL in target process\n");
	if (ThreadId != 0)
	{
		printf("[+] Injected thread id: %u for pid: %u\n", (UINT)ThreadId, (UINT)pid);
	}
	return 0;
}

