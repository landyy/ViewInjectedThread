#include "stdafx.h"
#include "helper.h"

void PrintBadThreads(MalicousThreads MalThreads, MalicousMemory MalMem) {

	using namespace std;

	if (MalThreads.BadThreadCount == 0) {
		wcout << L"[-] No Malicious Threads Detected" << endl;
	}
	else {

		wcout << L"[+] " << MalThreads.BadThreadCount << L"Potentially Malicious Threads Detected." << endl;
		wcout << endl;

		for (THREADENTRY32 te32 : MalThreads.BadThreadVector) {

			wcout << L"Process ID: " << te32.th32OwnerProcessID << endl;
			wcout << L"Thread ID:" << te32.th32ThreadID << endl;
			wcout << endl;

		}

	}

	VirtualMem Temp = MalMem.BadMemoryVector.at(0);

	if (Temp.LocalMem.size() == 0) {
		wcout << L"[-] No Malicious Memory Regions Detected" << endl;
	}
	else {
		wcout << L"[+] Potentially Malicious Memory Regions Detected." << endl;
		wcout << endl;

		for (VirtualMem Virtmem : MalMem.BadMemoryVector) {
			wcout << L"Process ID: " << Virtmem.Pid << endl;

			wcout << L"Memory Address with RWX:";

			for (unsigned char* LocalMem : Virtmem.LocalMem) {
				wcout << L"0x" << LocalMem << L"\n";
			}

			wcout << endl;
		}
	}

		wcout << L"Press Any Key To Continue...";
		getchar();
		return;
	




}