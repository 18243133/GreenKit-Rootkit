#pragma once
#include "stdafx.h"
#include <Windows.h>

#define DLL_PATH "\\GreenKit.dll" // METTRE ICI LA DLL
#define CREATE_THREAD_ACCESS (PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ) 


    BOOL HookProcess(HANDLE procName);
	DWORD GetTargetThreadIDFromProcName(HANDLE ProcName);
    bool Inject(HANDLE procName, char* dllName);
    bool Inject(DWORD pID, char* dllName);

