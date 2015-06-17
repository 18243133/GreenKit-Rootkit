#pragma once

#include "resource.h"
#include "process.h"
#include <Windows.h>
#include <string.h>
#include <stdio.h>
#include <winsock2.h>
#include "ZwOpenFile.h"
#include <string.h>
#include <iostream>
#include <winternl.h>
#pragma comment(lib, "ntdll")

#define STATUS_SUCCESS  ((NTSTATUS)0x00000000L)