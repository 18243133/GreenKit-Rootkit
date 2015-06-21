#ifndef NT_OPENFILE_H
# define NT_OPENFILE_H

# include "windefs.h"

typedef NTSTATUS(WINAPI *TD_NtCreateKey)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING, ULONG, PULONG);

NTSTATUS NTAPI NewNtCreateKey(
	PHANDLE				KeyHandle,
	ACCESS_MASK			DesiredAccess,
	POBJECT_ATTRIBUTES	ObjectAttributes,
	ULONG				TitleIndex,
	PUNICODE_STRING		Class,
	ULONG				CreateOptions,
	PULONG				Disposition);

#endif