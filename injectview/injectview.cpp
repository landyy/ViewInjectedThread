// injectview.cpp : Defines the entry point for the console application.
//


#include "stdafx.h"
#include "print.h"
#include "injectview.h"
#include "injectmem.h"
#include "system.h"


/*
FindInjectedThread

Loops through the threads of the process in question and exaimines the security
attributes of them

*/
MalicousThreads FindInjectedThread(DWORD Pid) {
	HANDLE ThreadSnap = NULL;
	THREADENTRY32 te32 = { 0 };
	te32.dwSize = sizeof(THREADENTRY32);
	HANDLE ThreadHandle;
	//HANDLE ProcessHandle;
	LONG64 StartAddress;
	MalicousThreads MalThreads;

	MalThreads.BadThreadCount = 0;

	bool IsProcessProtected = IsProtectedProcess(Pid);

	if (IsProcessProtected == true) {
		#ifdef DEBUG
		std::wcout << L"[!] Skipping Process " << Pid << L". Process is Protected" << std::endl;
		
		#endif

		return MalThreads;
	}

	//Get address of NtQueryInformationThread so we can use it
	NtQueryThreadPointer NtQueryInformationThread = (NtQueryThreadPointer)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationThread");

	//create a snapshot of the threads
	ThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	if (!Thread32First(ThreadSnap, &te32))
	{
		std::wcout << L"Error getting thread snapshot " << GetLastError() << std::endl;
		CloseHandle(ThreadSnap); 

		return MalThreads;
	}
	

	//loop through them and perform actions on them
	do {
		
		if (te32.th32OwnerProcessID == Pid) {
			
			#ifdef DEBUG
			
			std::wcout << L"[*] Checking Thread ID: " << te32.th32ThreadID << std::endl;
			
			#endif

			//get a handle to the thread
			ThreadHandle = OpenThread(THREAD_ALL_ACCESS, NULL, te32.th32ThreadID);
			
			StartAddress = 0;
			//get start address information on thread via NtQueryInformationThread
			DWORD NtStatus = NtQueryInformationThread(ThreadHandle, ThreadQuerySetWin32StartAddress, &StartAddress, sizeof(DWORD_PTR), NULL);

			if (!IsInAddressSpace(Pid, StartAddress)) {
				
				MalThreads.BadThreadVector.push_back(te32);
				MalThreads.BadThreadCount = MalThreads.BadThreadCount + 1;
			}

		}

	} while (Thread32Next(ThreadSnap, &te32));

	CloseHandle(ThreadSnap);

	return MalThreads;
}

/*
Main function

Takes command line arguments in as the process to be inspected.
*/
int wmain(int argc, wchar_t **argv)
{
	DWORD Pid = 0;
	MalicousThreads FinalMalThreads;
	VirtualMem FinalVirtualMem;
	MalicousMemory FinalMalMem;
	FinalMalThreads.BadThreadCount = 0;
	DWORD IntegReturn;

	//check argument count
	if (argc == 1 || argc > 3) {
		PrintUsage();
		return 0;
	}
	
	IntegReturn = GetProcessIntegrity();

	if (IntegReturn == 2) {
		return 0;
	}
	else if (IntegReturn == 1) {
		ElevateToSytem();
		return 0;
	}

	//start comparison for command line arguments here
	if (wcscmp(argv[1], L"--all") == 0 || wcscmp(argv[1], L"-a") == 0) {
		FindInjectedAll();
	}
	else if (wcscmp(argv[1], L"-h") == 0 || wcscmp(argv[1], L"--help") == 0) {
		PrintUsage();
	}

	else if(wcscmp(argv[1],L"--pid") == 0 || wcscmp(argv[1],L"-p") == 0){
		Pid = (DWORD)wcstod(argv[2], _T('\0'));
		FinalMalThreads = FindInjectedThread(Pid);
		FinalVirtualMem = FindInjectedMem(Pid);

		FinalMalMem.BadMemoryVector.push_back(FinalVirtualMem);

		PrintBadThreads(FinalMalThreads, FinalMalMem);

	}
	else {
		std::wcout << L"Invalid arguments" << std::endl;
		PrintUsage();
	}

	std::wcout << L"Press Any Key to Continue...";
	getchar();
	return 0;

}

