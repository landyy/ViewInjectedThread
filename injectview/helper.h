#pragma once

struct MalicousThreads
{
	DWORD BadThreadCount;
	std::vector<THREADENTRY32> BadThreadVector;
};

struct VirtualMem
{
	
	DWORD Pid;
	std::vector<unsigned char*> LocalMem;
};

struct MalicousMemory
{
	std::vector<VirtualMem> BadMemoryVector;
};

void PrintUsage();

void FindInjectedAll();

BOOL IsProtectedProcess(DWORD Pid);

BOOL IsInAddressSpace(DWORD Pid, DWORD ThreadAddress);

DWORD GetPIDByName(const wchar_t *ProcessName);