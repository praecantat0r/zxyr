#include "injection.h"

bool RtlCreateUserThread(HANDLE hProcess, LPCSTR DllPath) {

	LPVOID LoadLibraryAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA"); // Loads the address of LoadLibraryA from kernel32.dll

	if (!LoadLibraryAddr) {
		printf("Could not get the address of LoadLibraryA!\n");
		printf("Last Error: 0x%x", GetLastError());
		system("PAUSE");
		return false;
	}

	printf("LoadLibraryA is located at: 0x%x\n", (void*)LoadLibraryAddr);
	Sleep(1000);

	LPVOID pDllPath = VirtualAllocEx(hProcess, 0, strlen(DllPath), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); // Create space for the path to our DLL in the target process memory using VirtualAllocEx

	if (!pDllPath) {
		printf("Could not allocate memory in target process\n");
		printf("Last Error: 0x%x", GetLastError());
		printf("WuckyFucky @_@");
		system("PAUSE");
		return false;
	}
	printf("DLL path memory is located at: 0x%x\n", (void*)pDllPath);
	Sleep(1000);

	BOOL written = WriteProcessMemory(hProcess, pDllPath, (LPVOID)DllPath, strlen(DllPath), NULL); // We Write the DLL path into the memory we allocated using WriteProcessMemory

	if (!written) {
		printf("Could not write into allocated memory\n");
		printf("Last Error: 0x%x", GetLastError());
		printf("FuckyWucky 0w0");
		system("PAUSE");
		return false;
	}
	printf("Dll path was written at address: 0x%p\n", (void*)pDllPath);
	Sleep(1000);

	HMODULE modNtDll = GetModuleHandle("ntdll.dll"); // User-mode applications use the native system services routines by calling the entry points in the Ntdll.dll dynamic link library(Windows Docs)

	if (!modNtDll) {
		printf("No module handle for ntdll.dll\n");
		printf("Last Error: 0x%x\n", GetLastError());
		printf("Another one!");
		system("PAUSE");
		return false;
	}

	pRtlCreateUserThread pfunc_RtlCreateUserThread = (pRtlCreateUserThread)GetProcAddress(modNtDll, "RtlCreateUserThread"); // We try to get RtlCreateThreadEx function from ntdll.dll

	if (!pfunc_RtlCreateUserThread) {
		printf("Failed to get RtlCreateThreadEx function from ntdll.dll");
		printf("LastError: 0x%x\n", GetLastError());
		printf("FUCK");
		system("PAUSE");
		return false;
	}

	HANDLE hThread = NULL;

	pfunc_RtlCreateUserThread(
		hProcess,
		NULL,
		0,
		0,
		0,
		0,
		LoadLibraryAddr,
		pDllPath,
		&hThread,
		NULL
	); // We did the thingy!

	if (!hThread) {

		printf("\n RtlCreateUserThreadEx failed\!n");
		printf("Last Error 0x%x\n", GetLastError());
		printf("FFUCKFUCK\n");
		
		if (VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE)) {
			printf("Memory was freed in process\n");
			Sleep(1000);
		}
		system("PAUSE");
		return false;
	}

	printf("Thread started with RtlCreateUserThread\n");
	Sleep(1000);

	WaitForSingleObject(hThread, INFINITE);

	system("PAUSE");

	if (VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE)) {
		printf("Memory was freed in process\n");
		Sleep(1000);
	}

	CloseHandle(hThread);
	CloseHandle(hProcess);

	return true; //HELP ME HELP ME HELP ME HELP ME HELP ME

}
