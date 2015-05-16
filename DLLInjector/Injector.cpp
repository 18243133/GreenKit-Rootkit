#include "Injector.h"
#include <windows.h>
#include <tlhelp32.h>
#include <shlwapi.h>
#include <conio.h>
#include <stdio.h> 

Injector::Injector(void)
{
}


Injector::~Injector(void)
{
} 

#define CREATE_THREAD_ACCESS (PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ) 

bool Injector::Deploy()
{
    TCHAR currentDir[MAX_PATH];
    TCHAR dllDir[MAX_PATH];
    bool isSuccessful = true;
    GetCurrentDirectory(MAX_PATH, currentDir);

    strcpy(dllDir, currentDir);
    strcat(dllDir, DLL_PATH);

    printf("Current dir: %s\n", currentDir);
    printf("DLL path: %s\n", dllDir);
    printf("Target Process: %s\n", PROC_NAME);

    system("PAUSE");
    
    if (Inject(PROC_NAME, dllDir))
        printf("Injection successful!\n");
    else
    {
        printf("Couldn't inject the DLL...\n");
        isSuccessful = false;
    }

    system("PAUSE");
    return isSuccessful;
}

//use it with procName
bool Injector::Inject(char* procName,char* dllName)
{
    if (!procName)
        return false;

    if (!dllName)
        return false;

	DWORD pID = GetTargetThreadIDFromProcName(procName); 
    
   char DLL_NAME[MAX_PATH] = {0}; 
   GetFullPathName(dllName, MAX_PATH,DLL_NAME, NULL); 
   printf(DLL_NAME); 
   printf("\n");
   HANDLE processus = 0;
   HMODULE hLib = 0; 
   char buf[50] = {0}; 
   LPVOID RemoteString, LoadLibAddy; 

   processus = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pID); 
   if (!processus)
   { 
      sprintf(buf, "OpenProcess() failed: %d ", GetLastError()); 
      printf(buf); 
      return false; 
   } 
    
   LoadLibAddy = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA"); 

   // Allocate space in the target process for our DLL
   RemoteString = (LPVOID)VirtualAllocEx(processus, NULL, strlen(DLL_NAME), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

   // Write the string name of our <strong class="highlight">DLL</strong> in the memory allocated 
   WriteProcessMemory(processus, (LPVOID)RemoteString, DLL_NAME, strlen(DLL_NAME), NULL);

   // Load our DLL
   CreateRemoteThread(processus, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibAddy, (LPVOID)RemoteString, NULL, NULL);

   CloseHandle(processus);
   return true; 
}

//use it with procID
bool Injector::Inject(DWORD pID, char* dllName)
{
    if (!pID)
        return false;

    if (!dllName)
        return false;
    
   char DLL_NAME[MAX_PATH] = {0}; 
   GetFullPathName(dllName, MAX_PATH,DLL_NAME, NULL); 
   printf(DLL_NAME); 
   printf("\n");

   HANDLE process = 0; 
   HMODULE hLib = 0; 
   char buf[50] = {0}; 
   LPVOID RemoteString, LoadLibAddy; 

   process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pID);
   if (!process)
   { 
      sprintf(buf, "OpenProcess() failed: %d", GetLastError()); 
      MessageBox(NULL, buf, "Loader", MB_OK); 
      printf(buf); 
      return false; 
   } 
    
   LoadLibAddy = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA"); 

   // Allocate space in the target process for our DLL
   RemoteString = (LPVOID)VirtualAllocEx(process, NULL, strlen(DLL_NAME), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

   // Write the string name of our DLL in the memory allocated 
   WriteProcessMemory(process, (LPVOID)RemoteString, DLL_NAME, strlen(DLL_NAME), NULL);

   // Load our DLL
   CreateRemoteThread(process, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibAddy, (LPVOID)RemoteString, NULL, NULL);

   CloseHandle(process);
   return true; 
}

DWORD Injector::GetTargetThreadIDFromProcName(const char * ProcName)
{
	PROCESSENTRY32 pe;
	HANDLE thSnapShot;
	BOOL retval, ProcFound = false;
 
	thSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if(thSnapShot == INVALID_HANDLE_VALUE)
	{
		printf("Error: Couldn't create toolhelp snapshot!");
		return false;
	}
	pe.dwSize = sizeof(PROCESSENTRY32);
	retval = Process32First(thSnapShot, &pe);
	while(retval)
	{
		if(!strcmp(pe.szExeFile, ProcName))
			return pe.th32ProcessID;

		retval = Process32Next(thSnapShot, &pe);
	}
	return 0;
}

