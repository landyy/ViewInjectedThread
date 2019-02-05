#include "stdafx.h"
#include "helper.h"

using namespace std;


//return 0 if process is already SYSTEM
//return 1 if admin
//return 2 if medium or lower
DWORD GetProcessIntegrity() {

	HANDLE TokenHandle;
	DWORD LengthNeeded;
	PTOKEN_MANDATORY_LABEL TokenIntegrity;
	DWORD IntegrityLevel;
	

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &TokenHandle)) {

		wcout << L"[-] OpenProcessToken Failed on Current Process" << endl;

		return 2;

	}

	//dont check for error here because it will fail regardless. We need the buffer size so thats okay
	GetTokenInformation(TokenHandle, TokenIntegrityLevel, NULL, 0, &LengthNeeded);
		
	TokenIntegrity = (PTOKEN_MANDATORY_LABEL)GlobalAlloc(GPTR,LengthNeeded);

	if (!GetTokenInformation(TokenHandle, TokenIntegrityLevel, TokenIntegrity, LengthNeeded, &LengthNeeded)) {
		wcout << L"[-] GetTokenInformationFailed 2 with Error " << GetLastError() << endl;
		return 2;
	}

	//we can get the integrity level from the RID due to the fact that there are certain RIDs that will auto identify the process integrity
	//therefore we use the sid and get the rid from the sid
	IntegrityLevel = *GetSidSubAuthority(TokenIntegrity->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(TokenIntegrity->Label.Sid) - 1));

	#ifdef DEBUG

	wcout << IntegrityLevel << endl;


	if (IntegrityLevel == SECURITY_MANDATORY_LOW_RID)
	{
		// Low Integrity
		wprintf(L"Low Process\n");
	}
	else if (IntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID &&
		IntegrityLevel < SECURITY_MANDATORY_HIGH_RID)
	{
		// Medium Integrity
		wprintf(L"Medium Process\n");
	}
	else if (IntegrityLevel >= SECURITY_MANDATORY_HIGH_RID && 
		IntegrityLevel < SECURITY_MANDATORY_SYSTEM_RID)
	{
		// High Integrity
		wprintf(L"High Integrity Process\n");
	}
	else if (IntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID)
	{
		// System Integrity
		wprintf(L"System Integrity Process\n");
	}

	#endif
	if (IntegrityLevel < SECURITY_MANDATORY_HIGH_RID) {
		wcout << "[-] Process is Medium Integrity or lower. Please run as Administrator. Exiting..." << endl;
		GlobalFree(TokenIntegrity);
		return 1;
	}
	else if (IntegrityLevel >= SECURITY_MANDATORY_HIGH_RID &&
		IntegrityLevel < SECURITY_MANDATORY_SYSTEM_RID) {
		wcout << "[!] Process is High Integrity. Elevating to System." << endl;
		GlobalFree(TokenIntegrity);
		return 1;
	}
	else if (IntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID)
	{
		// System Integrity
		wcout << L"[!] Process is already SYSTEM. Skipping SYSTEM elevation" << endl;
		GlobalFree(TokenIntegrity);
		return 0;
	}
	GlobalFree(TokenIntegrity);
	return 2;

}

BOOL EnableDebugPrivs() {
	LUID Luid = {};
	TOKEN_PRIVILEGES TokenPrivs;
	HANDLE CurrentProcess = GetCurrentProcess();
	HANDLE CurrentToken = {};

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &Luid)) {
		return FALSE;
	}

	TokenPrivs.PrivilegeCount = 1;
	TokenPrivs.Privileges[0].Luid = Luid;
	TokenPrivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	
	if (!OpenProcessToken(CurrentProcess, TOKEN_ALL_ACCESS, &CurrentToken)) {
		return FALSE;
	}
	if (!AdjustTokenPrivileges(CurrentToken, FALSE, &TokenPrivs, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
		return FALSE;
	}

	return TRUE;
}

HANDLE GetAccessToken() {
	HANDLE ProcessHandle;
	HANDLE AccessToken;

	

	DWORD PidWinlogon = GetPIDByName(L"winlogon.exe");

	ProcessHandle = OpenProcess(PROCESS_QUERY_INFORMATION,TRUE, PidWinlogon);

	if (!ProcessHandle) {
		wcout << "OpenProcess on Winlogon failed with Error " << GetLastError() << endl;
		return NULL;
	}

	if (!OpenProcessToken(ProcessHandle, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY, &AccessToken)) {
		wcout << "OpenProcessToken on Winlogon failed with Error " << GetLastError() << endl;
		return NULL;
	}

	return AccessToken;

}

void ElevateToSytem() {

	SECURITY_IMPERSONATION_LEVEL SeLevel = SecurityImpersonation;
	TOKEN_TYPE TokenType = TokenPrimary;
	HANDLE NewToken = new HANDLE;
	STARTUPINFO si = {};
	PROCESS_INFORMATION pi = {};
	BOOL Result;


	Result = EnableDebugPrivs();
	if (!Result) {
		wcout << "[-] Could Not Enable Debug Privs" << endl;
	}

	HANDLE AccessToken = GetAccessToken();

	if (!AccessToken) {
		return;
	}

	if (!DuplicateTokenEx(AccessToken, MAXIMUM_ALLOWED, NULL, SeLevel, TokenType, &NewToken)) {
		wcout << "DuplicateToken on Winlogon failed with Error " << GetLastError() << endl;
	}



	wchar_t *CommandLine = GetCommandLine();

	CreateProcessWithTokenW(NewToken, LOGON_NETCREDENTIALS_ONLY, NULL, CommandLine, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);


}