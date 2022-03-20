#ifndef INJECTION_H
#define INJECTION_H

#define RTN_OK    0
#define RTN_USAGE 1
#define RTN_ERROR 13

#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>

#define DEBUG_NTBUFFER

bool GetOsInfo();

bool SetPrivilege(HANDLE hToken, LPCTSTR Privilege, BOOL bEnablePrivilege);
void DisplayError(LPCSTR szAPI);
int EscalatePrivilege();

bool RtlCreateUserThread(HANDLE hProcess, LPCSTR DllPath);

typedef DWORD(WINAPI* pRtlCreateUserThread) (

	IN		HANDLE					ProcessHandle,
	IN 		PSECURITY_DESCRIPTOR	SecurityDescriptor,
	IN		BOOLEAN					CreateSuspended,
	IN		ULONG					StackZeroBits,
	IN OUT	PULONG					StackReserved,
	IN OUT	PULONG					StackCommit,
	IN		PVOID					StartAddress,
	IN		PVOID					StartParameter,
	OUT		PHANDLE					ThreadHandle,
	OUT		PVOID					ClientID

	);

#endif



