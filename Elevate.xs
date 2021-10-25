/*
    # Win32::Elevate - Perl Win32 Elevation Facility
    #
    # Author: Daniel Just
 */
 
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <sddl.h>
#include <Lmcons.h>

#define PERL_NO_GET_CONTEXT
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"


/** C code goes here **/

/* 
	# C helper functions
	# Most of this code is adapted from
	# https://github.com/zer0cat/sys/blob/master/sys.c and
	# https://github.com/0x0luke/Elevat0r/blob/master/Elevat0r.cpp
*/


static bool EnableWindowsPrivilege(WCHAR* Privilege) {
	LUID luid = {0};
	TOKEN_PRIVILEGES tp;
	HANDLE currentToken,currentProcess = GetCurrentProcess();

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		if (!LookupPrivilegeValueW(NULL, Privilege, &luid)) 
			{
			wprintf(L"LookupPrivilegeValue failed %d\n",GetLastError());
			return FALSE;
			}
		if (!OpenProcessToken(currentProcess, TOKEN_ALL_ACCESS, &currentToken)) 		
			{
			wprintf(L"OpenProcessToken for priv8 failed %d\n",GetLastError());
			return FALSE;
			}
		if (!AdjustTokenPrivileges(currentToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) 
			{
			wprintf(L"AdjustTokenPrivileges failed %d\n",GetLastError());		
			return FALSE;
			}
		return TRUE;
}



static int GetSystemPid() {
	int dwPid = 0; // 
	HANDLE hSnapshot = NULL;
	PROCESSENTRY32W p_e;
	p_e.dwSize = sizeof(PROCESSENTRY32W);

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			if (hSnapshot == INVALID_HANDLE_VALUE) {
				wprintf(L"Error CreateToolhelp32Snapshot %d\n",GetLastError());
				return 0;
			}

			if (!Process32FirstW(hSnapshot, &p_e)) {
				wprintf(L"Error Process32FirstW %d\n",GetLastError());
				CloseHandle(hSnapshot);
				return 0;
			}

			do {
				if(lstrcmpiW(p_e.szExeFile,L"winlogon.exe") == 0) {
					dwPid = p_e.th32ProcessID;
					break;
				}
			} while(Process32NextW(hSnapshot, &p_e));

	CloseHandle(hSnapshot);
	return dwPid;
}




static bool haveAdmin() {
	bool res = false;
	HANDLE token = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
		TOKEN_ELEVATION elevation;
		DWORD size = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size)) {
			res = elevation.TokenIsElevated;
		}
	}
	if (token) {
		CloseHandle(token);
	}
	return res;
}



static HANDLE getTrustedInstallerPHandle() {
	HANDLE hSCManager, hTIService;
	SERVICE_STATUS_PROCESS lpServiceStatusBuffer = { 0 };

	hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT);
	hTIService = OpenServiceW(hSCManager, L"TrustedInstaller", SERVICE_START | SERVICE_QUERY_STATUS);

	if (hTIService == NULL)
		goto cleanup_and_fail;
	
	do {
		unsigned long ulBytesNeeded;
		QueryServiceStatusEx(hTIService, SC_STATUS_PROCESS_INFO, (unsigned char*)&lpServiceStatusBuffer, sizeof(SERVICE_STATUS_PROCESS), &ulBytesNeeded);
		
		if (lpServiceStatusBuffer.dwCurrentState == SERVICE_STOPPED)
			if (!StartService(hTIService, 0, NULL))
				goto cleanup_and_fail;

	} while (lpServiceStatusBuffer.dwCurrentState == SERVICE_STOPPED);

	CloseServiceHandle(hSCManager);
	CloseServiceHandle(hTIService);

	return OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, lpServiceStatusBuffer.dwProcessId);

cleanup_and_fail:
	CloseServiceHandle(hSCManager);
	CloseServiceHandle(hTIService);

	return NULL;
}

//////////////////////////////////



bool EnablePrivilege(bool impersonating, int privilege_value)
{
	bool b;
	NTSTATUS status = RtlAdjustPrivilege(privilege_value, true, impersonating, &b);
	return NT_SUCCESS(status);
}


bool ImpersonateTcbToken() {

	//Grabs a tcb token from WinLogon

	HANDLE hsnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hsnapshot == INVALID_HANDLE_VALUE) {
//		printf("[-] CreateToolhelp32Snapshot failed (%d)\n", GLE);
		return false;
	}

	PROCESSENTRY32W entry = { 0 };
	entry.dwSize = sizeof(entry);

	if (!Process32FirstW(hsnapshot, &entry)) {
		CloseHandle(hsnapshot);
//		printf("[-] Process32First failed (%d)\n", GLE);
		return false;
	}

	DWORD pid = 0;

	do {
		if (!_wcsicmp(L"winlogon.exe", entry.szExeFile)) {
			pid = entry.th32ProcessID;
			break;
		}
	} while (Process32NextW(hsnapshot, &entry));

	CloseHandle(hsnapshot);

	if (!pid) {
//		printf("[-] Failed to find winlogon\n");
		return false;
	}

	HANDLE hprocess = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
	if (!hprocess) {
//		printf("[-] OpenProcess on pid %d failed (%d)\n", pid, GLE);
		return false;
	}

	HANDLE htoken;
	bool token_success = OpenProcessToken(hprocess, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE, &htoken);

	CloseHandle(hprocess);

	if (!token_success) {
//		printf("[-] OpenProcessToken failed (%d)\n", GLE);
		return false;
	}

	bool impersonate_success = ImpersonateLoggedOnUser(htoken);

	CloseHandle(htoken);

	if (!impersonate_success) {
//		printf("[-] ImpersonateLoggedOnUser failed (%d)\n", GLE);
		return false;
	}

	return true;
}




static HANDLE GetTrustedInstallerToken() {

	bool impersonating = false;
	HANDLE trusted_installer_token = NULL;

	//ResolveDynamicFunctions();
	
	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	RtlAdjustPrivilege = (_RtlAdjustPrivilege)GetProcAddress(ntdll, "RtlAdjustPrivilege");
	
	do {

		//TcbPrivilege is required to specify groups when calling LogonUserExExW

		if (!EnablePrivilege(false, SeTcbPrivilege)) {
			if (!EnablePrivilege(false, SeDebugPrivilege)) {
//				printf("[-] The current process doesn't have SeTcbPrivilege or SeDebugPrivilege\n");
				break;
			}
			impersonating = ImpersonateTcbToken();
			if (!impersonating || !EnablePrivilege(impersonating, SeTcbPrivilege)) {
//				printf("[-] Failed to acquire SeTcbPrivilege\n");
				break;
			}
		}

		PSID trusted_installer_sid;
		if ( !ConvertStringSidToSidA("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", &trusted_installer_sid) ) {
//			printf("[-] ConvertStringSidToSidA failed (%d)\n", GLE);
			break;
		}

		HANDLE current_token = impersonating ? GetCurrentThreadToken() : GetCurrentProcessToken();

		DWORD token_group_size;
		GetTokenInformation(current_token, TokenGroups, NULL, 0, &token_group_size);
		PTOKEN_GROUPS token_groups = (PTOKEN_GROUPS)LocalAlloc(LPTR, token_group_size);
		if (!token_groups) {
//			printf("[-] LocalAlloc failed (%d)\n", GLE);
			break;
		}
		if ( !GetTokenInformation(current_token, TokenGroups, token_groups, token_group_size, &token_group_size) ) {
//			printf("[-] GetTokenInformation failed (%d)\n", GLE);
			break;
		}

		//LogonUserExExW will fail if we don't replace the mandatory label with the trusted installer sid, didn't bother looking into why.
		//The new token has the proper mandatory label anyways after we create it
		token_groups->Groups[token_groups->GroupCount - 1].Sid = trusted_installer_sid;
		token_groups->Groups[token_groups->GroupCount - 1].Attributes = SE_GROUP_OWNER | SE_GROUP_ENABLED;

		bool logon_success = LogonUserExExW((LPWSTR)L"SYSTEM", (LPWSTR)L"NT AUTHORITY", NULL, LOGON32_LOGON_SERVICE, LOGON32_PROVIDER_WINNT50, token_groups, &trusted_installer_token, NULL, NULL, NULL, NULL);

		if ( !logon_success )
//			printf("LogonUserExExW failed (error %d)\n", GLE);

	} while (false);

	if (impersonating)
		RevertToSelf();

	return trusted_installer_token;

}





static bool isUser(wchar_t *userName) {
	wchar_t actualName[UNLEN + 1];
  DWORD actualName_len = UNLEN + 1;
  GetUserNameW(actualName, &actualName_len);
	return wcscmp(actualName, userName);
}


// END C helper functions




/*
	Return codes -
	  0 - Successful elevation
		1 - No admin rights
		2 - Failed acquiring SeDebugPrivilege
		4 - Could not start/open a System or TrustedInstaller service
		5 - Could not acquire token
		6 - Impersonation with token failed
		7 - Unknown input argument
 */

// elevationType can only be "SYSTEM" or "TI"
static int getElevation(char *elevationType) {
	/* There are four steps involved in getting system privileges
		 1. Get DebugPrivilege
		 2. Create or find a Process with the desired access level (e.g. SYSTEM)
		 3. Make a copy of it's access token
		 4. Impersonate own process with that token
	*/
	
	
	// Step 0: Check if we are elevated (admin rights)
	if ( !haveAdmin() ) {
		return 1;
	}
	
	
	// Step 1: Get DebugPrivilege
	if ( !EnableWindowsPrivilege(L"SeDebugPrivilege") ) {
		return 2;
	}
	
	
	// Step 2: Create or find a process with desired access level
	HANDLE hProcess,TokenHandle,phNewToken;
	SECURITY_ATTRIBUTES TokenAttributes =
		{
			.lpSecurityDescriptor = NULL,
			.bInheritHandle = FALSE,
			.nLength = sizeof(SECURITY_ATTRIBUTES)
		}; //if don't have c99 compiler, change this definition
	DWORD dAccess = PROCESS_QUERY_LIMITED_INFORMATION; //in win10 use this instead PROCESS_QUERY_INFORMATION;

	if ( strcmp(elevationType, "SYSTEM") == 0 ) {
		// Getting a System Process handle
		DWORD dwProcessId = GetSystemPid();
		if ( dwProcessId == 0 ) {
			return 4;
		}

		hProcess = OpenProcess(dAccess, FALSE, dwProcessId);
		if ( hProcess == NULL ) {
			return 4;
		}
		
	} else if ( strcmp(elevationType, "TI") == 0 ) {
		// Getting the TI process handle
		
		// Check if we are SYSTEM, become SYSTEM otherwise
		if ( !isUser(L"NT AUTHORITY\\SYSTEM") ) {
			int res = getElevation("SYSTEM");
			if ( res != 0 ) {
				return res;
			}
		}
		
		htoken = GetTrustedInstallerToken();
		if ( htoken == NULL ) {
			return 4;
		}
		
		if ( !ImpersonateLoggedOnUser(htoken) ) {
			return 6;
		}
		return 0;
		
	} else {
		// Unknown input argument
		return 7;
	}


	// Step 3: Get and make a copy of the access token
	if ( !OpenProcessToken(hProcess, MAXIMUM_ALLOWED, &TokenHandle) ) {
		return 5;
	}

	dAccess = TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY;
	if ( !DuplicateTokenEx(TokenHandle, dAccess, &TokenAttributes, SecurityImpersonation, TokenPrimary, &phNewToken) ) {
		return 5;
	}

	
	// Step 4: Use copied token to elevate ourselves
	if ( !ImpersonateLoggedOnUser(phNewToken) ) {
		return 6;
	}

	
	// SetThreadToken(NULL, pNewToken);  // is this needed?
	
	return 0; // everything went swimmingly
}

// static int getTI() {

	// return 0; // everything went swimmingly
// }


// static int getAdmin() {
	
	// return 0; // everything went swimmingly
// }



/** XSUB code goes here **/


MODULE = Win32::Elevate		PACKAGE = Win32::Elevate		


int
ToSystem()
    CODE:
        RETVAL = getElevation("SYSTEM");
		OUTPUT:
				RETVAL

int
ToTI()
    CODE:
        RETVAL = getElevation("TI");
		OUTPUT:
				RETVAL
				
bool
DeElevate()
		CODE:
				RETVAL = RevertToSelf();
		OUTPUT:
				RETVAL
				
				