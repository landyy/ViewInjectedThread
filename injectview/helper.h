#pragma once

void PrintUsage();

void FindInjectedAll();

BOOL IsProtectedProcess(DWORD Pid);

BOOL IsInAddressSpace(DWORD Pid, DWORD ThreadAddress);