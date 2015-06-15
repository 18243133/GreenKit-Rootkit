// GreenKit.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "GreenKit.h"
#include "process.h"
#include <Windows.h>
#include <string.h>
#include <stdio.h>
#include <winsock2.h>

BYTE hook[6];

extern "C" __declspec(dllexport) void InitGreenKit()
{
    MessageBox(0, "I'm initialized!", "Message from Greenkit!", 0);
}

DWORD HookFunction(LPCSTR lpModule, LPCSTR lpFuncName, LPVOID lpFunction)
{
    BYTE jmp[6] = { 0xe9, //jmp
        0x00, 0x00, 0x00, 0x00, //address
        0xc3 //ret
    };
    DWORD dwAddr = (DWORD)GetProcAddress(GetModuleHandle(lpModule), lpFuncName);
    ReadProcessMemory(GetCurrentProcess(), (LPVOID)dwAddr, (unsigned char *) hook, 6, 0);
    DWORD dwCalc = ((DWORD)lpFunction - dwAddr - 5);
    memcpy(&jmp[1], &dwCalc, 4);
    WriteProcessMemory(GetCurrentProcess(), (LPVOID)dwAddr, jmp, 6, 0);
    return dwAddr;
}

BOOL UnHookFunction(LPCSTR lpModule, LPCSTR lpFuncName)
{
    DWORD dwAddr = (DWORD)GetProcAddress(GetModuleHandle(lpModule), lpFuncName);
    if (WriteProcessMemory(GetCurrentProcess(), (LPVOID)dwAddr, (unsigned char *) hook, 6, 0))
        return TRUE;
    return FALSE;
}

int WINAPI nMessageBox(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType)
{
    UnHookFunction("user32.dll", "MessageBoxA");
    int result = MessageBox(0, lpText, "hooked with our own function", MB_OK);
    HookFunction("user32.dll", "MessageBoxA", nMessageBox);
    return result;
}

INT APIENTRY DllMain(HMODULE hDLL, DWORD Reason, LPVOID Reserved)
{
    DWORD procID = GetCurrentProcessId();
    char buffer[64];
    wsprintf(buffer, "Injected on process %d", procID);
    HookFunction("user32.dll", "MessageBoxA", nMessageBox);
    InitGreenKit();
    UnHookFunction("user32.dll", "MessageBoxA");
    MessageBox(0, buffer, "I AM A FREE FUNCTIONNN", 0);
    return TRUE;
}