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
    DWORD procID = GetCurrentProcessId();
    char buffer[64];
    wsprintf(buffer, "Injected on process %d", procID);
    MessageBox(0, buffer, "DLL Injection Successful!", 0);
    return TRUE;
}

extern "C" __declspec(dllexport) void InitGreenKit()
{
    MessageBox(0, "I'm initialized!", "Message from Greenkit!", 0);
}