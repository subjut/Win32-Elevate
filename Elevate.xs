/*
    # Win32::Elevate - Perl Win32 Elevation Facility
    #
    # Author: Daniel Just
 */
 
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
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
	# https://github.com/lab52io/StopDefender/blob/master/StopDefender/StopDefender.cpp
*/



/*
	Sets requested privilege for input token.
	Returns true if successful, false otherwise.
*/
static BOOL SetPrivilege(
	HANDLE hToken,					// access token handle
	LPCWSTR lpszPrivilege,		// name of privilege to enable/disable
	BOOL bEnablePrivilege		// to enable or disable privilege
)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValueW(
		NULL,					// lookup privilege on local system
		lpszPrivilege,		// privilege to lookup 
		&luid))				// receives LUID of privilege
	{
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;


	// Enable the privilege or disable all privileges
	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		return FALSE;
	}

	return TRUE;
}


/*
	Starts the TrustedInstaller service.
	Returns true if successful, false otherwise.
*/
static BOOL StartTrustedInstallerService() {
	// Get a handle to the SCM database. 
	SC_HANDLE schSCManager = OpenSCManager(
		NULL,                    // local computer
		NULL,                    // servicesActive database 
		SC_MANAGER_ALL_ACCESS);  // full access rights 

	if ( NULL == schSCManager )
	{
		return FALSE;
	}

	// Get a handle to the service.
	SC_HANDLE schService = OpenServiceW(
		schSCManager,         // SCM database 
		L"TrustedInstaller",  // name of service 
		SERVICE_START);  // full access 

	if ( schService == NULL )
	{
		CloseServiceHandle(schSCManager);
		return FALSE;
	}

	// Attempt to start the service.
	if ( !StartService(
		schService,  // handle to service 
		0,           // number of arguments 
		NULL))      // no arguments 
	{
		CloseServiceHandle(schService);
		CloseServiceHandle(schSCManager);
		return FALSE;
	}

//	Sleep(2000);
	CloseServiceHandle(schService);
	CloseServiceHandle(schSCManager);

	return TRUE;
}


/*
	Searches for a running process by name.
	Returns it's PID if found, 0 (zero) otherwise.
*/
static int GetProcessByName(char *name)
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
			if ( strcmp(process.szExeFile, name) == 0 )
			{
				return process.th32ProcessID;
			}
		} while (Process32Next(snapshot, &process));
	}

	CloseHandle(snapshot);

	return 0;
}


/*
	Checks if current process is running with elevated administrative privileges.
	Returns true if so, false if not.
*/
static bool isAdmin() {
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


// END C helper functions




/*
	Elevates current process to SYSTEM access rights or current thread
	to TrustedInstaller access rights. If elevationType is "TI",
	TrustedInstaller elevation is attempted. Any other input value is ignored
	and SYSTEM elevation is attempted.
	
	Return codes -
		0  - Successful impersonation
		1  - No admin rights
		2  - Failed to acquire SeDebugPrivilege
		3  - Failed to start TrustedInstaller Service
		4  - Failed to open Winlogon process (for SYSTEM elevation)
		5  - Failed to acquire Winlogon token
		6  - Failed to open TrustedInstaller process
		7  - Failed to acquire TrustedInstaller token
		8  - Failed to impersonate SYSTEM with token
		9  - Failed to impersonate TrustedInstaller with token
		10 - Failed to adjust current thread privileges
 */
static int getElevation(char *elevationType) {
	/* There are four steps involved in getting system privileges
		 1. Get DebugPrivilege
		 2. Create or find a Process with the desired access level (e.g. SYSTEM)
		 3. Make a copy of it's access token
		 4. Impersonate own process with that token
	*/
	
	// Step 0: Check if we are elevated (admin rights)
	if ( !isAdmin() )
	{
		return 1;
	}
	
	// Initialize variables and structures
	HANDLE tokenHandle = NULL;
	HANDLE threadTokenHandle = NULL;
	STARTUPINFO startupInfo;
	PROCESS_INFORMATION processInformation;
	ZeroMemory(&startupInfo, sizeof(STARTUPINFO));
	ZeroMemory(&processInformation, sizeof(PROCESS_INFORMATION));
	startupInfo.cb = sizeof(STARTUPINFO);


	// Step 1: Add SE debug privilege
	HANDLE currentTokenHandle = NULL;
	BOOL getCurrentToken = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &currentTokenHandle);
	if ( !SetPrivilege(currentTokenHandle, L"SeDebugPrivilege", TRUE) )
	{
		return 2;
	}

	
	// Step 2: [Create and] open needed processes
	if ( strcmp(elevationType, "TI") == 0 )
	{
		// TrustedInstaller might already be running
		if( !GetProcessByName("TrustedInstaller.exe") )
		{
			// Starting TI service from SC Manager
			if ( !StartTrustedInstallerService() )
			{
				return 3;
			}
		}
	}


	// Searching for Winlogon PID 
	DWORD PID_TO_IMPERSONATE = GetProcessByName("lsass.exe");

	if ( PID_TO_IMPERSONATE == 0 )
	{
		return 4;
	}
	
	DWORD PID_TO_IMPERSONATE_TI = 0;
	if ( strcmp(elevationType, "TI") == 0 )
	{
		// Searching for TrustedInstaller PID 
		PID_TO_IMPERSONATE_TI = GetProcessByName("TrustedInstaller.exe");

		if ( PID_TO_IMPERSONATE_TI == 0 )
		{
			return 4;
		}
	}

	
	// Call OpenProcess() to open WINLOGON
	HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION, true, PID_TO_IMPERSONATE);
	if ( processHandle == NULL )
	{
		return 4;
	}

	
	// Step 3: Get a copy of required tokens [SYSTEM]
	BOOL getToken = OpenProcessToken(processHandle, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &tokenHandle);
	if ( !getToken )
	{
		return 5;
	}
	

	// Step 4: Impersonate user in a thread [SYSTEM]
	BOOL impersonateUser = ImpersonateLoggedOnUser(tokenHandle);
	if ( !impersonateUser )
	{
		return 8;
	}
		
	
	// Step 5: Adjust privileges to be able to read and write registry
	BOOL getThreadToken = OpenThreadToken(GetCurrentThread(), TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, FALSE, &threadTokenHandle);
	
	if ( !SetPrivilege(threadTokenHandle, L"SeRestorePrivilege", TRUE) )
	{
		return 10;
	}
	if ( !SetPrivilege(threadTokenHandle, L"SeBackupPrivilege", TRUE) )
	{
		return 10;
	}
	
	
	// Closing unnecessary handles
	CloseHandle(processHandle);
	CloseHandle(tokenHandle);
	CloseHandle(threadTokenHandle);


	if ( strcmp(elevationType, "TI") == 0 )
	{
		// Call OpenProcess() to open TRUSTEDINSTALLER
		processHandle = OpenProcess(PROCESS_QUERY_INFORMATION, true, PID_TO_IMPERSONATE_TI);
		if ( !processHandle )
		{
			return 6;
		}

		// Call OpenProcessToken()
		getToken = OpenProcessToken(processHandle, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &tokenHandle);
		if ( !getToken )
		{
			return 7;
		}

		// Impersonate user in a thread
		impersonateUser = ImpersonateLoggedOnUser(tokenHandle);
		if ( !impersonateUser )
		{
			return 9;
		}
		
		// Step 5: Adjust privileges to be able to read and write registry
		getThreadToken = OpenThreadToken(GetCurrentThread(), TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, FALSE, &threadTokenHandle);
		
		if ( !SetPrivilege(threadTokenHandle, L"SeRestorePrivilege", TRUE) )
		{
			return 10;
		}
		if ( !SetPrivilege(threadTokenHandle, L"SeBackupPrivilege", TRUE) )
		{
			return 10;
		}
	}

	return 0; // everything went swimmingly
}



/** Start of code from WIN32
	The following is from the WIN32 module.
	It is only used for the package tests so we don't have to depend on WIN32.
*/

#ifndef countof
#  define countof(array) (sizeof (array) / sizeof (*(array)))
#endif

SV *
wstr_to_sv(pTHX_ WCHAR *wstr)
{
    int wlen = (int)wcslen(wstr)+1;
    BOOL use_default = FALSE;
    int len = WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, wstr, wlen, NULL, 0, NULL, NULL);
    SV *sv = sv_2mortal(newSV(len));

    len = WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, wstr, wlen, SvPVX(sv), len, NULL, &use_default);
    if (use_default) {
        len = WideCharToMultiByte(CP_UTF8, 0, wstr, wlen, NULL, 0, NULL, NULL);
        sv_grow(sv, len);
        len = WideCharToMultiByte(CP_UTF8, 0, wstr, wlen, SvPVX(sv), len, NULL, NULL);
        SvUTF8_on(sv);
    }
    /* Shouldn't really ever fail since we ask for the required length first, but who knows... */
    if (len) {
        SvPOK_on(sv);
        SvCUR_set(sv, len-1);
    }
    return sv;
}


XS(w32_LoginName)
{
    dXSARGS;
    WCHAR name[128];
    DWORD size = countof(name);

    if (items)
	Perl_croak(aTHX_ "usage: Win32::Elevate::LoginName()");

    EXTEND(SP,1);

    if (GetUserNameW(name, &size)) {
        ST(0) = wstr_to_sv(aTHX_ name);
        XSRETURN(1);
    }

    XSRETURN_UNDEF;
}


/* Use explicit struct definition because wSuiteMask and
 * wProductType are not defined in the VC++ 6.0 headers.
 * WORD type has been replaced by unsigned short because
 * WORD is already used by Perl itself.
 */
struct g_osver_t {
    DWORD dwOSVersionInfoSize;
    DWORD dwMajorVersion;
    DWORD dwMinorVersion;
    DWORD dwBuildNumber;
    DWORD dwPlatformId;
    CHAR  szCSDVersion[128];
    unsigned short wServicePackMajor;
    unsigned short wServicePackMinor;
    unsigned short wSuiteMask;
    BYTE  wProductType;
    BYTE  wReserved;
} g_osver = {0, 0, 0, 0, 0, "", 0, 0, 0, 0, 0};
BOOL g_osver_ex = TRUE;

/** End of code from WIN32 **/



/** XSUB code goes below next line **/
MODULE = Win32::Elevate		PACKAGE = Win32::Elevate		


int
BecomeSystem()
	CODE:
		if ( getElevation("SYSTEM") ) {
			RETVAL = 0;
		} else {
			RETVAL = 1;
		}
	OUTPUT:
		RETVAL

int
BecomeTI()
	CODE:
		if ( getElevation("TI") ) {
			RETVAL = 0;
		} else {
			RETVAL = 1;
		}
	OUTPUT:
		RETVAL


bool
RevertToSelf()
	CODE:
		RETVAL = RevertToSelf();
	OUTPUT:
		RETVAL



# The following is, again, from the WIN32 module.
BOOT:
{
	const char *file = __FILE__;

    if (g_osver.dwOSVersionInfoSize == 0) {
        g_osver.dwOSVersionInfoSize = sizeof(g_osver);
        if (!GetVersionExA((OSVERSIONINFOA*)&g_osver)) {
            g_osver_ex = FALSE;
            g_osver.dwOSVersionInfoSize = sizeof(OSVERSIONINFOA);
            GetVersionExA((OSVERSIONINFOA*)&g_osver);
        }
    }
	 
	newXS("Win32::Elevate::LoginName", w32_LoginName, file);
	XSRETURN_YES;
}
