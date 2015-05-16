#pragma once
#include <Windows.h>

#define DLL_PATH "\\ExampleDLL.dll" // METTRE ICI LA DLL
#define PROC_NAME "iexplore.exe" 

class Injector
{
public:
	Injector(void);
	~Injector(void);

	bool Inject(char* procName,char* dllName);
	bool Inject(DWORD pID,char* dllName);
    bool Deploy();

private:
	DWORD GetTargetThreadIDFromProcName(const char * ProcName);
};

