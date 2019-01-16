// injectview.cpp : Defines the entry point for the console application.
//


#include "stdafx.h"
#include "print.h"
#include "injectview.h"


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
	HANDLE ProcessHandle;
	LONG64 StartAddress;
	MalicousThreads MalThreads;
	MEMORY_BASIC_INFORMATION MemBasic;
	SYSTEM_INFO SysBasic;
	SIZE_T VirtualQueryBuf;

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

			ProcessHandle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, Pid);

			unsigned char *LocalMem = NULL;

			GetSystemInfo(&SysBasic);

			for (LocalMem = NULL; VirtualQueryBuf = VirtualQueryEx(ProcessHandle, LocalMem, &MemBasic, sizeof(MemBasic)) == sizeof(MemBasic); LocalMem += MemBasic.RegionSize) {

				if (MemBasic.State == MEM_FREE) {
					#ifdef DEBUG
					std::wcout << L"Memory Region " << LocalMem << " has been Freed. Skipping. " << std::endl;
					#endif
					continue;
				}


				#ifdef DEBUG
				std::wcout << L"[!] Memory Region " << LocalMem << L" has protection";

				switch (MemBasic.Protect) {
					case PAGE_EXECUTE:
						std::wcout << L" PAGE_EXECUTE";
						break;
					case PAGE_EXECUTE_READ:
						std::wcout << L" PAGE_EXECUTE_READ";
						break;
					case PAGE_EXECUTE_READWRITE:
						std::wcout << L" PAGE_EXECUTE_READWRITE";
						break;
					case PAGE_EXECUTE_WRITECOPY:
						std::wcout << L" PAGE_EXECUTE_WRITECOPY";
						break;
					case PAGE_NOACCESS:
						std::wcout << L" PAGE_NOACCESS";
						break;
					case PAGE_READONLY:
						std::wcout << L" PAGE_READONLY";
						break;
					case PAGE_READWRITE:
						std::wcout << L" PAGE_READWRITE";
						break;
					case PAGE_WRITECOPY:
						std::wcout << L" PAGE_WRITECOPY";
						break;
					default:
						std::wcout << L"[-] Memory protection unknown";
				}
				std::wcout << std::endl;
				#endif
				


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
	FinalMalThreads.BadThreadCount = 0;

	//check argument count
	if (argc == 1 || argc > 3) {
		PrintUsage();
		return 0;
	}
	
	//start comparison for command line arguments here
	if (wcscmp(argv[1], L"--all") == 0) {
		FindInjectedAll();
		return 0;
	}
	else if (wcscmp(argv[1], L"-h") == 0 || wcscmp(argv[1], L"--help") == 0) {
		PrintUsage();
		return 0;
	}

	else if(wcscmp(argv[1],L"--pid") == 0 || wcscmp(argv[1],L"-p") == 0){
		Pid = (DWORD)wcstod(argv[2], _T('\0'));
		FinalMalThreads = FindInjectedThread(Pid);

		PrintBadThreads(FinalMalThreads);

	}
	else {
		std::wcout << L"Invalid arguments" << std::endl;
		PrintUsage();
	}

	return 0;

}

