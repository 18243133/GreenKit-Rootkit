#include "stdafx.h"
#include "process.h"

// GLOBALS
DWORD dwGKPID;

BOOL process_allSuspendApplyResume(APPLY aFunc) {
	HANDLE hSnapP;
	PROCESSENTRY32 pe32;

	if (INVALID_HANDLE_VALUE == (hSnapP = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)))
		return FALSE;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (FALSE == Process32First(hSnapP, &pe32)) {
		if (ERROR_NO_MORE_FILES == GetLastError()) // No process running apparently
			return TRUE;
		return FALSE;
	}
	
	dwGKPID = GetCurrentProcessId();
	while (TRUE) {
		DWORD dwPID = pe32.th32ProcessID;
		if (dwGKPID != dwPID) { // Lets not suspend ourself
			if (pe32.cntThreads > 0)
				process_suspendOrResumeAllThreads(dwPID, TRUE);

			if (pe32.cntThreads > 0)
			process_suspendOrResumeAllThreads(dwPID, FALSE);
		}

		if (FALSE == (Process32Next(hSnapP, &pe32)))
			break;
	}

	return TRUE;
}

BOOL process_suspendOrResumeAllThreads(DWORD dwPID, BOOL bSuspend) {
	HANDLE hSnapT;
	HANDLE hT;
	THREADENTRY32 te32;

	if (INVALID_HANDLE_VALUE == (hSnapT = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)))
		return FALSE;

	te32.dwSize = sizeof(THREADENTRY32);
	if (FALSE == Thread32First(hSnapT, &te32)) {
		return TRUE;
	}

	while (TRUE) {
		if (dwPID == te32.th32OwnerProcessID) {
			OutputDebugStringA("\Found thread of process\r\n");
			if (NULL == (hT = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID))) {
				OutputDebugStringA("\Failed to open thread.\r\n");
				// GetLastError(); exploit this
				break;
			}

			if (bSuspend) {
				if (-1 == SuspendThread(hT)) // Failed to suspend thread
					break;
				OutputDebugStringA("\t\tSuspend Thread OK\r\n");
			}
			else {
				if (-1 == ResumeThread(hT)) // Failed to suspend thread
					break;
				OutputDebugStringA("\t\tResume Thread OK\r\n");
			}
		}

		if (FALSE == (Thread32Next(hSnapT, &te32)))
			break;
	}

	return TRUE;
}