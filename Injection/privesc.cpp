#include "injection.h"

bool SetPrivilege(HANDLE hToken, LPCTSTR Privilege, BOOL bEnablePrivilege) {

	TOKEN_PRIVILEGES tp;
	LUID luid;
	TOKEN_PRIVILEGES tpPrevious;
	DWORD cbPrevious = sizeof(TOKEN_PRIVILEGES);

	if (!LookupPrivilegeValue(NULL, Privilege, &luid)) return false;

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = 0;

	AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		&tpPrevious,
		&cbPrevious);

	if (GetLastError() != ERROR_SUCCESS) return false;

	tpPrevious.PrivilegeCount = 1;
	tpPrevious.Privileges[0].Luid = luid;

	if (bEnablePrivilege) {
		tpPrevious.Privileges[0].Attributes |= (SE_PRIVILEGE_ENABLED);
	}
	else {
		tpPrevious.Privileges[0].Attributes ^= (SE_PRIVILEGE_ENABLED & tpPrevious.Privileges[0].Attributes);
	}

	AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tpPrevious,
		cbPrevious,
		NULL,
		NULL
	);

	if (GetLastError() != ERROR_SUCCESS) return false;

	return true;
}

void DisplayError(LPCSTR szAPI) {

	LPTSTR MessageBuffer;
	DWORD dwBufferLength;


	if (dwBufferLength = FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,
		GetLastError(),
		GetSystemDefaultLangID(),
		(LPTSTR)&MessageBuffer,
		0,
		NULL
	)) {

		DWORD dwBytesWritten;

		WriteFile(

			GetStdHandle(STD_ERROR_HANDLE),
			MessageBuffer,
			dwBufferLength,
			&dwBytesWritten,
			NULL
		);

		LocalFree(MessageBuffer);
	}
}

int EscalatePrivilege() {
	HANDLE hToken;
	int dwRetVal = RTN_OK;

	if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken)) {
		if (GetLastError() == ERROR_NO_TOKEN) {
			if (!ImpersonateSelf(SecurityImpersonation)) return RTN_ERROR;

			if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken)) {

				DisplayError("OpenThreadToken");
				return RTN_ERROR;
			}
		}
		else {
			return RTN_ERROR;
		}
	}

	if (!SetPrivilege(hToken, SE_DEBUG_NAME, TRUE)) {

		DisplayError("Set Privilege");

		CloseHandle(hToken);

		return RTN_ERROR;
	}
	return dwRetVal;
}
