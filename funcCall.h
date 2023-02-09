#pragma once

#include <windows.h>
#include <malloc.h>

HMODULE WINAPI hlpGetModuleHandle(LPCWSTR sModuleName);
FARPROC WINAPI hlpGetProcAddress(HMODULE hMod, char * sProcName);
int FindTarget();
HANDLE FindThread(int pid);
void XOR(char* data, size_t data_len, char* key, size_t key_len);
