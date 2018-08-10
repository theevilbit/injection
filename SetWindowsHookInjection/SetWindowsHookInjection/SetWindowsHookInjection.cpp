// SetWindowsHookInjection.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "general.h"
#include <psapi.h>
#include <stdio.h>
#include <Windows.h>

int wmain(int argc, wchar_t**argv) //to read in arguments as unicode
{
	if (argc != 4)
	{
		printf("Usage: SetWindowsHookInjection.exe [window name] [dll path] [function name]\r\n");
		return -1;
	}

	//load the DLL
	HMODULE hDLL = LoadLibraryEx(argv[2], NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (hDLL == NULL)
	{
		ErrorExit(TEXT("LoadLibraryEx"));
	}
	printf("[+] Handle to the DLL: 0x%Ix\r\n", (SIZE_T)hDLL);
	char func[256];
	sprintf(func, "%ws", argv[3]);

	HOOKPROC addr = (HOOKPROC)GetProcAddress(hDLL, func);
	if (addr == NULL)
	{
		ErrorExit(TEXT("GetProcAddress"));
	}
	printf("[+] function address: 0x%Ix\r\n", (SIZE_T)addr);


	HWND hWindow = FindWindow(NULL, argv[1]);
	if (hWindow == NULL)
	{
		ErrorExit(TEXT("FindWindow"));
	}
	printf("[+] Handle to the Window: 0x%Ix\r\n", (SIZE_T)hWindow);

	DWORD pid = 0;
	DWORD tid = GetWindowThreadProcessId(hWindow, &pid);
	if(pid == 0)
	{
		ErrorExit(TEXT("GetWindowThreadProcessId"));
	}
	printf("[+] PID, TID: 0x%Ix, 0x%Ix\r\n", (SIZE_T)pid, (SIZE_T)tid);

	HHOOK handle = SetWindowsHookEx(WH_KEYBOARD, addr, hDLL, tid);
	if (handle == NULL)
	{
		ErrorExit(TEXT("SetWindowsHookEx"));
	}
	
	printf("[+] Press enter to unhook the function and exit\r\n");
	getchar();
	UnhookWindowsHookEx(handle);
    return 0;
}

