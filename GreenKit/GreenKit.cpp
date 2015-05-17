// GreenKit.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "GreenKit.h"
#include "process.h"
#include <Windows.h>
#include <string.h>
#include <stdio.h>

INT APIENTRY DllMain(HMODULE hDLL, DWORD Reason, LPVOID Reserved)
{
    /* CODE EXECUTED WHEN THE DLL IS LOADED*/

    /* Create a temp.txt file text for TESTING PURPOSE ONLY */
    /* open file */
    FILE *file;
    fopen_s(&file, "C:\\temp.txt", "a+");

    switch (Reason) {
    case DLL_PROCESS_ATTACH:
        fprintf(file, "DLL attach function called.\n");
        break;
    case DLL_PROCESS_DETACH:
        fprintf(file, "DLL detach function called.\n");
        break;
    case DLL_THREAD_ATTACH:
        fprintf(file, "DLL thread attach function called.\n");
        break;
    case DLL_THREAD_DETACH:
        fprintf(file, "DLL thread detach function called.\n");
        break;
    }

    /* close file */
    fclose(file);

    //process_allSuspendApplyResume(NULL);
    return TRUE;
}