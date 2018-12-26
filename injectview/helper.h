#pragma once

struct MalicousThreads
{
	DWORD BadThreadCount;
	std::vector<THREADENTRY32> BadThreadVector;
};

void PrintUsage();

void FindInjectedAll();

BOOL IsProtectedProcess(DWORD Pid);

BOOL IsInAddressSpace(DWORD Pid, DWORD ThreadAddress);