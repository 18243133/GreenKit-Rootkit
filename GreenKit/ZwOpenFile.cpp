#include "stdafx.h"

/* use with 

_NtCreateFile NtCreateFile = (_NtCreateFile)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtCreateFile");
_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlInitUnicodeString");

see http://www.sysnative.com/forums/programming/8592-ntcreatefile-example.html 

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
*/