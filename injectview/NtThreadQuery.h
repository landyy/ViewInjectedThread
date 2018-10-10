#pragma once
#include <Windows.h>

typedef NTSTATUS(WINAPI *pNtQIT)(HANDLE, LONG, PVOID, ULONG, PULONG);

#define ThreadQuerySetWin32StartAddress 9

