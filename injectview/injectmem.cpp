#include "stdafx.h"
#include "print.h"
#include "injectview.h"
#include "injectmem.h"

VirtualMem FindInjectedMem(DWORD Pid) {

	HANDLE ProcessHandle;
	MEMORY_BASIC_INFORMATION MemBasic;
	SYSTEM_INFO SysBasic;
	SIZE_T VirtualQueryBuf;
	VirtualMem VirtMem;


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

		if (MemBasic.Protect == PAGE_EXECUTE_READWRITE) {

			#ifdef DEBUG
			std::wcout << "[!] Memory Region with RWE Deteteced at" << LocalMem << ". Potentially Malicous." << std::endl;
			#endif

			VirtMem.LocalMem.push_back(LocalMem);

		}
	}

	VirtMem.Pid = Pid;

	return VirtMem;
}