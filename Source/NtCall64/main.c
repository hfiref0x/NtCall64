/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2019
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.33
*
*  DATE:        22 Nov 2019
*
*  Program entry point.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "main.h"

#define PARAM_LOG           "-log"
#define PARAM_WIN32K        "-win32k"
#define PARAM_SYSCALL       "-call"
#define PARAM_PASSCOUNT     "-pc"
#define PARAM_HELP          "-help"

//
// Help output.
//
#define T_HELP	"Usage: -help [-win32k][-log][-call Id][-pc Value][-wt Value][-s]\r\n\
  -help     - Show this help information;\r\n\
  -log      - Enable logging to file last call parameters;\r\n\
  -win32k   - Fuzz win32k graphical subsystem table, otherwise fuzz ntos table;\r\n\
  -call Id  - Fuzz syscall by supplied numeric <Id> (can be from any table). All blacklists are ignored;\r\n\
  -pc Value - Set number of passes for each service to <Value>, default value 65536;\r\n\
  -wt Value - Set wait timeout for calling threads in seconds (except single syscall fuzzing), default value is 30;\r\n\
  -s        - Attempt to run program from LocalSystem account.\r\n\n\
Example: ntcall64.exe -win32k -log"

//
// Global context.
//
NTCALL_CONTEXT g_ctx;

typedef struct _PRIVSET {
    ULONG Privilege;
    LPCSTR Name;
} PRIVSET, *PPRIVSET;

PRIVSET g_privs[] = {
    { SE_CREATE_TOKEN_PRIVILEGE, "SE_CREATE_TOKEN_PRIVILEGE" },
    { SE_ASSIGNPRIMARYTOKEN_PRIVILEGE, "SE_ASSIGNPRIMARYTOKEN_PRIVILEGE" },
    { SE_LOCK_MEMORY_PRIVILEGE, "SE_LOCK_MEMORY_PRIVILEGE" },
    { SE_INCREASE_QUOTA_PRIVILEGE, "SE_INCREASE_QUOTA_PRIVILEGE" },
    { SE_MACHINE_ACCOUNT_PRIVILEGE, "SE_MACHINE_ACCOUNT_PRIVILEGE" },
    { SE_TCB_PRIVILEGE, "SE_TCB_PRIVILEGE" },
    { SE_SECURITY_PRIVILEGE, "SE_SECURITY_PRIVILEGE" },
    { SE_TAKE_OWNERSHIP_PRIVILEGE, "SE_TAKE_OWNERSHIP_PRIVILEGE" },
    { SE_LOAD_DRIVER_PRIVILEGE, "SE_LOAD_DRIVER_PRIVILEGE"},
    { SE_SYSTEM_PROFILE_PRIVILEGE, "SE_SYSTEM_PROFILE_PRIVILEGE"},
    { SE_SYSTEMTIME_PRIVILEGE, "SE_SYSTEMTIME_PRIVILEGE"},
    { SE_PROF_SINGLE_PROCESS_PRIVILEGE, "SE_PROF_SINGLE_PROCESS_PRIVILEGE" },
    { SE_INC_BASE_PRIORITY_PRIVILEGE, "SE_INC_BASE_PRIORITY_PRIVILEGE" },
    { SE_CREATE_PAGEFILE_PRIVILEGE, "SE_CREATE_PAGEFILE_PRIVILEGE" },
    { SE_CREATE_PERMANENT_PRIVILEGE, "SE_CREATE_PERMANENT_PRIVILEGE" },
    { SE_BACKUP_PRIVILEGE, "SE_BACKUP_PRIVILEGE" },
    { SE_RESTORE_PRIVILEGE, "SE_RESTORE_PRIVILEGE" },
    { SE_SHUTDOWN_PRIVILEGE, "SE_SHUTDOWN_PRIVILEGE" },
    { SE_DEBUG_PRIVILEGE, "SE_DEBUG_PRIVILEGE" },
    { SE_AUDIT_PRIVILEGE, "SE_AUDIT_PRIVILEGE" },
    { SE_SYSTEM_ENVIRONMENT_PRIVILEGE, "SE_SYSTEM_ENVIRONMENT_PRIVILEGE" },
    { SE_CHANGE_NOTIFY_PRIVILEGE, "SE_CHANGE_NOTIFY_PRIVILEGE" },
    { SE_REMOTE_SHUTDOWN_PRIVILEGE, "SE_REMOTE_SHUTDOWN_PRIVILEGE" },
    { SE_UNDOCK_PRIVILEGE, "SE_UNDOCK_PRIVILEGE" },
    { SE_SYNC_AGENT_PRIVILEGE, "SE_SYNC_AGENT_PRIVILEGE" },
    { SE_ENABLE_DELEGATION_PRIVILEGE, "SE_ENABLE_DELEGATION_PRIVILEGE" },
    { SE_MANAGE_VOLUME_PRIVILEGE, "SE_MANAGE_VOLUME_PRIVILEGE" },
    { SE_IMPERSONATE_PRIVILEGE, "SE_IMPERSONATE_PRIVILEGE" },
    { SE_CREATE_GLOBAL_PRIVILEGE, "SE_CREATE_GLOBAL_PRIVILEGE" },
    { SE_TRUSTED_CREDMAN_ACCESS_PRIVILEGE, "SE_TRUSTED_CREDMAN_ACCESS_PRIVILEGE" },
    { SE_RELABEL_PRIVILEGE, "SE_RELABEL_PRIVILEGE" },
    { SE_INC_WORKING_SET_PRIVILEGE, "SE_INC_WORKING_SET_PRIVILEGE" },
    { SE_TIME_ZONE_PRIVILEGE, "SE_TIME_ZONE_PRIVILEGE" },
    { SE_CREATE_SYMBOLIC_LINK_PRIVILEGE, "SE_CREATE_SYMBOLIC_LINK_PRIVILEGE" }
};


/*
* VehHandler
*
* Purpose:
*
* Vectored exception handler.
*
*/
LONG CALLBACK VehHandler(
    EXCEPTION_POINTERS *ExceptionInfo
)
{
    HMODULE hModule = GetModuleHandle(TEXT("kernel32.dll"));
    if (hModule) {
        ExceptionInfo->ContextRecord->Rip = (DWORD64)GetProcAddress(hModule, "ExitThread");
    }
    return EXCEPTION_CONTINUE_EXECUTION;
}

/*
* FuzzInitPhase2
*
* Purpose:
*
* Load system image, locate table and start fuzzing.
*
*/
void FuzzInitPhase2(
    _In_ NTCALL_CONTEXT *Context
)
{
    BOOL probeWin32k = Context->ProbeWin32k;
    ULONG d;

    WCHAR szBuffer[MAX_PATH * 2];

    FuzzShowMessage("[+] Entering FuzzInitPhase2()\r\n",
        FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);

    _strcpy(szBuffer, Context->szSystemDirectory);
    if (probeWin32k) {
        _strcat(szBuffer, TEXT("\\win32k.sys"));
    }
    else {
        _strcat(szBuffer, TEXT("\\ntoskrnl.exe"));
    }

    Context->SystemImageBase = (ULONG_PTR)LoadLibraryEx(szBuffer, NULL, 0);

    if (Context->SystemImageBase == 0) {
        FuzzShowMessage("[!] Could not preload system image, abort!\r\n",
            FOREGROUND_RED | FOREGROUND_INTENSITY);
        return;
    }

    if (probeWin32k) {

        if (!FuzzFind_W32pServiceTable((HMODULE)Context->SystemImageBase, &Context->ServiceTable)) {
            FuzzShowMessage("[!] Could not find W32pServiceTable, abort!\r\n",
                FOREGROUND_RED | FOREGROUND_INTENSITY);
            return;
        }

        if (!FuzzLookupWin32kNames(szBuffer, Context)) {
            FuzzShowMessage("[!] Win32k names query error, abort!\r\n",
                FOREGROUND_RED | FOREGROUND_INTENSITY);
            return;
        }
    }
    else {

        Context->hNtdll = (ULONG_PTR)GetModuleHandle(TEXT("ntdll.dll"));
        if (Context->hNtdll == 0) {
            FuzzShowMessage("[!] Ntdll not found, abort!\r\n",
                FOREGROUND_RED | FOREGROUND_INTENSITY);
            return;
        }

        if (!FuzzFind_KiServiceTable(Context->SystemImageBase, &Context->ServiceTable)) {
            FuzzShowMessage("[!] KiServiceTable not found, abort!\r\n",
                FOREGROUND_RED | FOREGROUND_INTENSITY);
            return;
        }
    }

    //
    // Validate syscall id.
    //
    if (Context->ProbeSingleSyscall) {

        d = Context->SingleSyscallId;

        if (Context->ProbeWin32k) {
            d -= W32SYSCALLSTART;
        }

        if (d >= Context->ServiceTable.CountOfEntries) {

            FuzzShowMessage("[!] Syscall number exceeds current system available range.\r\n",
                FOREGROUND_RED | FOREGROUND_INTENSITY);
            return;

        }

    }

    FuzzRun(Context);

    FreeLibrary((HMODULE)Context->SystemImageBase);

    FuzzShowMessage("[-] Leaving FuzzInitPhase2()\r\n",
        FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
}

/*
* FuzzInitPhase1
*
* Purpose:
*
* Initial preparations for probing.
*
*/
VOID FuzzInitPhase1(
    _In_ BOOL probeWin32k,
    _In_ BOOL enableLog,
    _In_ BOOL singleSyscall,
    _In_ ULONG singleSyscallId,
    _In_ ULONG waitTimeout,
    _In_ ULONG64 passCount
)
{
    BOOLEAN bWasEnabled = FALSE;
    WORD wColor = 0;
    UINT i;

    DWORD lastError = 0;

    BOOL LogEnabled = FALSE;
    CHAR szOut[MAX_PATH * 2];
    RTL_OSVERSIONINFOW osver;

    FuzzShowMessage("[+] Entering FuzzInitPhase1()\r\n",
        FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);

    g_ctx.LogHandle = INVALID_HANDLE_VALUE;
    g_ctx.ThreadWaitTimeout = waitTimeout;

    if (g_ctx.IsLocalSystem)
        FuzzShowMessage("[+] LocalSystem account\r\n", 0);

    if (g_ctx.IsUserInAdminGroup) {
        FuzzShowMessage("[+] User is admin\r\n", 0);

        if (g_ctx.IsElevated) {
            FuzzShowMessage("[+] NtCall64 runs elevated.\r\n", 0);
        }
        else {
            FuzzShowMessage("[+] NtCall64 is not elevated, some privileges can not be adjusted.\r\n", 0);
        }
    }

    RtlSecureZeroMemory(g_ctx.szSystemDirectory, sizeof(g_ctx.szSystemDirectory));
    if (!GetSystemDirectory(g_ctx.szSystemDirectory, MAX_PATH)) {
        FuzzShowMessage("[!] Could not query system directory, abort!\r\n",
            FOREGROUND_RED | FOREGROUND_INTENSITY);
        return;
    }

    //
    // Show current directory.
    //
    RtlSecureZeroMemory(szOut, sizeof(szOut));
    _strcpy_a(szOut, "[+] Current directory: ");
    GetCurrentDirectoryA(MAX_PATH, _strend_a(szOut));
    _strcat_a(szOut, "\r\n");
    FuzzShowMessage(szOut, 0);

    //
    // Show command line.
    //
    FuzzShowMessage("[+] Command line -> \r\n\r\n", 0);
    FuzzShowMessage(GetCommandLineA(), 0);
    FuzzShowMessage("\r\n\r\n", 0);

    //
    // Show version logo if possible.
    //
    osver.dwOSVersionInfoSize = sizeof(osver);
    RtlGetVersion(&osver);

    _strcpy_a(szOut, "[~] Windows version: ");
    ultostr_a(osver.dwMajorVersion, _strend_a(szOut));
    ultostr_a(osver.dwMinorVersion, _strcat_a(szOut, "."));
    ultostr_a(osver.dwBuildNumber, _strcat_a(szOut, "."));
    _strcat_a(szOut, "\r\n");
    FuzzShowMessage(szOut, 0);

    if (enableLog) {

        LogEnabled = FuzzOpenLog(&g_ctx.LogHandle, &lastError);

        if (!LogEnabled) {

            _strcpy_a(szOut, "[!] Cannot open COM port for logging, GetLastError() = ");
            ultostr_a(lastError, _strend_a(szOut));              
            _strcat_a(szOut, ", logging disabled\r\n");

            FuzzShowMessage(szOut,
                FOREGROUND_RED | FOREGROUND_INTENSITY);

        }
        else
            FuzzShowMessage("[+] Logging enabled\r\n",
                FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);

        g_ctx.LogEnabled = LogEnabled;

    }
    else {
        g_ctx.LogEnabled = FALSE;
    }

    //
    // Handle single system call.
    //
    if (singleSyscall) {
        g_ctx.ProbeWin32k = (singleSyscallId >= W32SYSCALLSTART);
        g_ctx.ProbeSingleSyscall = TRUE;
        g_ctx.SingleSyscallId = singleSyscallId;
    }

    //
    // Remember pass count.
    //
    g_ctx.SyscallPassCount = passCount;
    _strcpy_a(szOut, "[+] Number of passes for each syscall = ");
    u64tostr_a(passCount, _strend_a(szOut));
    _strcat_a(szOut, "\r\n");
    FuzzShowMessage(szOut, 0);

    //
    // Show wait timeout.
    //
    _strcpy_a(szOut, "[+] Wait timeout for caller threads (seconds) = ");
    ultostr_a(waitTimeout, _strend_a(szOut));
    _strcat_a(szOut, "\r\n");
    FuzzShowMessage(szOut, 0);


    Sleep(2000);

    //
    // Assign much possible privileges if can.
    //
    for (i = 0; i < _countof(g_privs); i++) {
        _strcpy_a(szOut, "[*] Privilege ");
        _strcat_a(szOut, g_privs[i].Name);

        if (NT_SUCCESS(RtlAdjustPrivilege(g_privs[i].Privilege, TRUE, FALSE, &bWasEnabled))) {
            _strcat_a(szOut, " adjusted\r\n");
            wColor = FOREGROUND_GREEN | FOREGROUND_INTENSITY;
        }
        else {
            _strcat_a(szOut, " not adjusted\r\n");
            wColor = FOREGROUND_RED | FOREGROUND_BLUE;
        }
        FuzzShowMessage(szOut, wColor);
    }

    if (probeWin32k) {
        g_ctx.ProbeWin32k = TRUE;

        FuzzShowMessage("[*] Will be probing win32k table.\r\n",
            FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        Sleep(1000);

        BlackListCreateFromFile(&g_ctx.BlackList, CFG_FILE, (LPCSTR)"win32k");
    }
    else {
        FuzzShowMessage("[*] Will be probing ntoskrnl table.\r\n",
            FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        Sleep(1000);

        BlackListCreateFromFile(&g_ctx.BlackList, CFG_FILE, (LPCSTR)"ntos");
    }

    FuzzInitPhase2(&g_ctx);

    //
    // Cleanup.
    //

    BlackListDestroy(&g_ctx.BlackList);

    if (LogEnabled) {
        FuzzShowMessage("[-] Logging stop\r\n", 0);
        FuzzCloseLog(&g_ctx.LogHandle);
    }

    if (g_ctx.Win32pServiceTableNames)
        HeapFree(GetProcessHeap(), 0, g_ctx.Win32pServiceTableNames);

    FuzzShowMessage("[-] Leaving FuzzInitPhase1()\r\n", 
        FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
}

/*
* FuzzInitPhase0
*
* Purpose:
*
* Parse command line options.
*
*/
VOID FuzzInitPhase0(
    VOID
)
{
    BOOL probeWin32k = FALSE;
    BOOL enableLog = FALSE;
    BOOL singleSyscall = FALSE;
    ULONG singleSyscallId = 0;
    ULONG waitTimeout = FUZZ_THREAD_TIMEOUT_SEC;
    ULONG64 passCount = FUZZ_PASS_COUNT;

    TCHAR text[200];

    do {

        FuzzShowMessage("[+] Entering FuzzInitPhase0()\r\n",
            FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);

        RtlSecureZeroMemory(&g_ctx, sizeof(g_ctx));
        g_ctx.IsLocalSystem = IsLocalSystem();
        if (g_ctx.IsLocalSystem) {
            g_ctx.IsElevated = TRUE;
            g_ctx.IsUserInAdminGroup = TRUE;
        }
        else {
            g_ctx.IsUserInAdminGroup = IsUserInAdminGroup();
            if (g_ctx.IsUserInAdminGroup) {
                g_ctx.IsElevated = IsElevated(NULL);
            }
        }

        if (GetCommandLineOption(TEXT("-s"), FALSE, NULL, 0)) {
            if (g_ctx.IsLocalSystem == FALSE) {
                if (g_ctx.IsUserInAdminGroup == FALSE) {
                    FuzzShowMessage("[~] Administrative privileges reqruied for this operation\r\n", 0);
                    break;
                }
                if (g_ctx.IsElevated == FALSE) {
                    FuzzShowMessage("[~] Elevation required to start as LocalSystem\r\n", 0);
                    break;
                }
                FuzzShowMessage("[~] Restarting as LocalSystem\r\n", 0);
                RunAsLocalSystem();
                break;
            }
            //
            // Already LocalSystem, skip.
            //
        }

        probeWin32k = GetCommandLineOption(TEXT("-win32k"), FALSE, NULL, 0);
        enableLog = GetCommandLineOption(TEXT("-log"), FALSE, NULL, 0);

        RtlSecureZeroMemory(text, sizeof(text));
        if (GetCommandLineOption(TEXT("-call"), TRUE, text, sizeof(text) / sizeof(TCHAR)))
        {
            singleSyscall = TRUE;
            singleSyscallId = strtoul(text);
        }

        RtlSecureZeroMemory(text, sizeof(text));
        if (GetCommandLineOption(TEXT("-pc"), TRUE, text, sizeof(text) / sizeof(TCHAR)))
        {
            passCount = strtou64(text);
        }
        if (passCount == 0)
            passCount = FUZZ_PASS_COUNT;

        if (singleSyscall && probeWin32k) {
            FuzzShowMessage("Invalid combination of command line arguments.\r\n", 0);
            break;
        }

        RtlSecureZeroMemory(text, sizeof(text));
        if (GetCommandLineOption(TEXT("-wt"), TRUE, text, sizeof(text) / sizeof(TCHAR)))
        {
            waitTimeout = strtoul(text);
        }
        if (waitTimeout == 0)
            waitTimeout = FUZZ_THREAD_TIMEOUT_SEC;

        FuzzInitPhase1(
            probeWin32k, 
            enableLog, 
            singleSyscall, 
            singleSyscallId, 
            waitTimeout, 
            passCount);

    } while (FALSE);

    FuzzShowMessage("[-] Leaving FuzzInitPhase0()\r\n", 
        FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
}


/*
* main
*
* Purpose:
*
* Program main, process command line options and run fuzzing.
*
*/
UINT NtCall64Main()
{
    PVOID ExceptionHandler;

    FuzzShowMessage("NtCall64, Windows NT x64 syscall fuzzer, based on NtCall by Peter Kosyh.\r\n\n", 0);

    ExceptionHandler = RtlAddVectoredExceptionHandler(1, &VehHandler);
    if (ExceptionHandler) {

        do {

            if (GetCommandLineOption(TEXT("-help"), FALSE, NULL, 0)) {
                FuzzShowMessage(T_HELP, 0);
                break;
            }

            FuzzInitPhase0();
            FuzzShowMessage("Bye!\r\n", 0);

        } while (FALSE);

        RtlRemoveVectoredExceptionHandler(ExceptionHandler);
    }

    return 0;
}

/*
* main
*
* Purpose:
*
* Program EntryPoint.
*
*/
#if !defined(__cplusplus)
#pragma comment(linker, "/ENTRY:main")
void main()
{
    ExitProcess(NtCall64Main());
}
#else
#pragma comment(linker, "/ENTRY:WinMain")
int CALLBACK WinMain(
    _In_ HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_ LPSTR     lpCmdLine,
    _In_ int       nCmdShow
)
{
    UNREFERENCED_PARAMETER(hInstance);
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);
    UNREFERENCED_PARAMETER(nCmdShow);
    ExitProcess(NtCall64Main());
}
#endif
