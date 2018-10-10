// injectview.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

/*
FindInjectedThread

Loops through the threads of the process in question and exaimines the security
attributes of them

*/
void FindInjectedThread(DWORD Pid) {
	HANDLE ThreadSnap = NULL;
	THREADENTRY32 te32 = { 0 };
	te32.dwSize = sizeof(THREADENTRY32);

	//create a snapshot of the threads
	ThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	if (!Thread32First(ThreadSnap, &te32))
	{
		std::wcout << L"Error getting thread snapshot " << GetLastError() << std::endl;
		CloseHandle(ThreadSnap);     
		return;
	}

	//loop through them and perform actions on them
	do {
		
		if (te32.th32OwnerProcessID == Pid) {
			std::wcout << Pid << L" has Thread ID: " <<  te32.th32ThreadID << std::endl;
		}

	} while (Thread32Next(ThreadSnap, &te32));

	CloseHandle(ThreadSnap);

}

/*
Main function

Takes command line arguments in as the process to be inspected.
*/
int wmain(int argc, wchar_t **argv)
{
	
	if (argc == 1 || argc > 3) {
		std::wcout << L"Usage: " << argv[0] << L" PID" << std::endl;
		return 0;
	}
	
	DWORD Pid = wcstod(argv[1], _T('\0'));

	FindInjectedThread(Pid);

	return 0;

}

