#pragma once
#include <Windows.h>

#define DLL_PATH "\\ExampleDLL.dll" // METTRE ICI LA DLL

class Injector
{
public:
	Injector(void);
	~Injector(void);

	bool Inject(char* procName,char* dllName);
	bool Inject(DWORD pID,char* dllName);
    bool HookProcess(char* procName);

private:
	DWORD GetTargetThreadIDFromProcName(const char * ProcName);
};

