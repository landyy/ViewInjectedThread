
#include "stdafx.h"
#include "injectview.h"
#include "injectmem.h"
#include "print.h"

void PrintUsage() {
	std::wcout << L"Usage: " << L"./injectview" << L" [-ph]" << std::endl;
}

void FindInjectedAll() {

	HANDLE ProcessSnap = NULL;
	PROCESSENTRY32 pe32 = { 0 };
	pe32.dwSize = sizeof(PROCESSENTRY32);
	MalicousThreads TempMalThreads;
	MalicousThreads FinalMalThreads;
	VirtualMem TempVirtualMem;
	MalicousMemory FinalMem;

	FinalMalThreads.BadThreadCount = 0;
	TempMalThreads.BadThreadCount = 0;

	ProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	do {

		if (pe32.th32ProcessID != 0) {

			//create a list using vectors to keep track of all the bad threads
			//THIS NEEDS TO BE TESTED A LOT MORE
			// 1.) what if the first vector for virtual mem vector is empty but the next one is not
			// 2.) does this actually work?
			// 3.) test with multiple injection
			TempMalThreads = FindInjectedThread(pe32.th32ProcessID);
			FinalMalThreads.BadThreadVector.insert(FinalMalThreads.BadThreadVector.end(), TempMalThreads.BadThreadVector.begin(), TempMalThreads.BadThreadVector.end());

			//look at the memory region for the process
			TempVirtualMem = FindInjectedMem(pe32.th32ProcessID);
			FinalMem.BadMemoryVector.push_back(TempVirtualMem);
		}

	} while (Process32Next(ProcessSnap, &pe32));

	//Now print the results
//	PrintBadThreads(FinalMalThreads);

}

//based on https://github.com/sochka/ProcessMonitor/blob/master/ProcessMonitor.cpp
//this is really annoying and dumb extra code but this will only work if we get the correct function with the correct arch type :(
BOOL IsProtectedProcess(DWORD Pid) {

	HANDLE ProcessHandle;
	ULONG PsExtendedInfoBuf;
	NTSTATUS Status = 0;
	BOOL IsWow64 = false;
	NtQueryProcessInformationPointer NtQueryProcessInformation;
	
	ProcessHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Pid);

	//check if the handle is NULL
	if (ProcessHandle == NULL) {
		std::wcout << L"[-] OpenProcess Exited with Error " << GetLastError() << L" at PID: " << Pid << std::endl;
		return true;
	}

	//determine if we are running in WOW64, which means this is a 64 bit process
	IsWow64Process(GetCurrentProcess(), &IsWow64);

	
	if (IsWow64) {

		PROCESS_EXTENDED_BASIC_INFORMATION_WOW64 PsExtendedInfo64;

		//here we are a 64 bit app
		//Get address of ZwQueryProcessInformation so we can use it
		NtQueryProcessInformation = (NtQueryProcessInformationPointer)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtWow64QueryInformationProcess64");

		Status = NtQueryProcessInformation(ProcessHandle, ProcessBasicInformation, &PsExtendedInfo64, sizeof(PROCESS_EXTENDED_BASIC_INFORMATION_WOW64), &PsExtendedInfoBuf);

		return PsExtendedInfo64.IsProtectedProcess;

	}
	else {

		PROCESS_EXTENDED_BASIC_INFORMATION PsExtendedInfo;

		//here we are a 32 bit app
		//Get address of ZwQueryProcessInformation so we can use it
		NtQueryProcessInformation = (NtQueryProcessInformationPointer)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationProcess");

		Status = NtQueryProcessInformation(ProcessHandle, ProcessBasicInformation, &PsExtendedInfo, sizeof(PROCESS_EXTENDED_BASIC_INFORMATION), &PsExtendedInfoBuf);

		return PsExtendedInfo.IsProtectedProcess;

	}

}

BOOL IsInAddressSpace(DWORD Pid, DWORD ThreadAddress) {
	HANDLE ProcessHandle;
	HANDLE ModuleSnapshot;
	//DWORD cbneeded;
	MODULEENTRY32 me32 = { 0 };
	me32.dwSize = sizeof(MODULEENTRY32);

	ProcessHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, Pid);

	if (ProcessHandle == NULL) {
		std::wcout << L"OpenProcess Exited with Error " << GetLastError() << L" at PID: " << Pid << std::endl;
		return true;
	}

	ModuleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, Pid);

	if (ModuleSnapshot == NULL) {
		std::wcout << L"ModuleSnapshot Failed " << GetLastError() << L" at PID: " << Pid << std::endl;
		return true;
	}

	if (!Module32First(ModuleSnapshot, &me32))
	{
		CloseHandle(ModuleSnapshot);
		return true;
	}

	//  Now walk the module list of the process, 
	//  and display information about each module 
	do
	{

		DWORD max = (DWORD)me32.modBaseAddr + me32.modBaseSize;

		if (ThreadAddress >= (DWORD)me32.modBaseAddr && ThreadAddress <= max) {
			return true;
		}
		else {
			continue;
		}

	} while (Module32Next(ModuleSnapshot, &me32));


	return false;
}