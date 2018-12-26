#include "stdafx.h"
#include "helper.h"

void PrintBadThreads(MalicousThreads MalThreads) {

	using namespace std;

	if (MalThreads.BadThreadCount == 0) {
		wcout << L"No Malicious Threads Detected" << endl;

		wcout << L"Press Any Key To Continue...";
		getchar();
		return;
	}
	else {

		wcout << MalThreads.BadThreadCount << L" Potentially Malicious Threads Detected." << endl;
		wcout << endl;
		
		for (THREADENTRY32 te32 : MalThreads.BadThreadVector) {

			wcout << L"Process ID: " << te32.th32OwnerProcessID << endl;
			wcout << L"Thread ID:" << te32.th32ThreadID << endl;
			wcout << endl;

		}

		wcout << L"Press Any Key To Continue...";
		getchar();
		return;
	}




}