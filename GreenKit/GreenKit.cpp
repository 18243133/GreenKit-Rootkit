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
    
    return TRUE;
}

__declspec(dllexport) INT AAAAAAAAAAGreenKit()
{
    return 0;
}