#ifndef NTQUERYSYSTEMINFORMATION_H
# define NTQUERYSYSTEMINFORMATION_H

# include "windefs.h"

typedef NTSTATUS(WINAPI *TD_NtQuerySystemInformation)(
    __in       SYSTEM_INFORMATION_CLASS SystemInformationClass,
    __inout    PVOID SystemInformation,
    __in       ULONG SystemInformationLength,
    __out_opt  PULONG ReturnLength
    );

NTSTATUS WINAPI NewNtQuerySystemInformation(
	__in       SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__inout    PVOID                    SystemInformation,
	__in       ULONG                    SystemInformationLength,
	__out_opt  PULONG                   ReturnLength
	);

TD_NtQuerySystemInformation GetHookNtQuery();
VOID SetHookNtQuery(TD_NtQuerySystemInformation p_HookNtQuery);
VOID SetOldHookNtQuery(TD_NtQuerySystemInformation p_OldHookNtQuery);
TD_NtQuerySystemInformation GetOldHookNtQuery();

#endif
