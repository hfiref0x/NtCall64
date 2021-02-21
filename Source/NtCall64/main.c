/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2021
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.35
*
*  DATE:        21 Feb 2021
*
*  Program entry point.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

#define PARAM_LOG           TEXT("-log")
#define PARAM_LOGPORT       TEXT("-pname")
#define PARAM_LOGFILE       TEXT("-ofile")
#define PARAM_WIN32K        TEXT("-win32k")
#define PARAM_SYSCALL       TEXT("-call")
#define PARAM_PASSCOUNT     TEXT("-pc")
#define PARAM_WAITTIMEOUT   TEXT("-wt")
#define PARAM_HELP          TEXT("-help")
#define PARAM_LOCALSYSTEM   TEXT("-s")

#define DEFAULT_LOG_PORT    TEXT("COM1")
#define DEFAULT_LOG_FILE    TEXT("ntcall64.log")

#define WELCOME_BANNER      "NtCall64, Windows NT x64 syscall fuzzer, based on NtCall by Peter Kosyh.\r\n"
#define VERSION_BANNER      "Version 1.3.5 from 21 Feb 2021\r\n\n"

//
// Help output.
//
#define T_HELP	"Usage: -help [-win32k][-log [-pname][-ofile]][-call Id][-pc Value][-wt Value][-s]\r\n\
  -help     - Show this help information;\r\n\
  -log      - Enable logging to file last call parameters;\r\n\
  -pname    - Port name for logging, default COM1 (-log enabled required, mutual exclusive with -ofile);\r\n\
  -ofile    - File name for logging, default ntcall64.log (-log enabled required, mutual exclusive with -pname);\r\n\
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
NTCALL_LOG_PARAMS g_Log;

typedef struct _PRIVSET {
    ULONG Privilege;
    LPCSTR Name;
} PRIVSET, * PPRIVSET;

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
    EXCEPTION_POINTERS* ExceptionInfo
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
    _In_ NTCALL_CONTEXT* Context
)
{
    BOOL probeWin32k = Context->ProbeWin32k;
    ULONG d;

    WCHAR szBuffer[MAX_PATH * 2];

    ConsoleShowMessage("[+] Entering FuzzInitPhase2()\r\n",
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
        ConsoleShowMessage("[!] Could not preload system image, abort!\r\n",
            FOREGROUND_RED | FOREGROUND_INTENSITY);
        return;
    }

    if (probeWin32k) {

        if (!FuzzFindW32pServiceTable((HMODULE)Context->SystemImageBase, &Context->ServiceTable)) {
            ConsoleShowMessage("[!] Could not find W32pServiceTable, abort!\r\n",
                FOREGROUND_RED | FOREGROUND_INTENSITY);
            return;
        }

        if (!FuzzLookupWin32kNames(szBuffer, Context)) {
            ConsoleShowMessage("[!] Win32k names query error, abort!\r\n",
                FOREGROUND_RED | FOREGROUND_INTENSITY);
            return;
        }
    }
    else {

        Context->hNtdll = (ULONG_PTR)GetModuleHandle(TEXT("ntdll.dll"));
        if (Context->hNtdll == 0) {
            ConsoleShowMessage("[!] Ntdll not found, abort!\r\n",
                FOREGROUND_RED | FOREGROUND_INTENSITY);
            return;
        }

        if (!FuzzFindKiServiceTable(Context->SystemImageBase, &Context->ServiceTable)) {
            ConsoleShowMessage("[!] KiServiceTable not found, abort!\r\n",
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

            ConsoleShowMessage("[!] Syscall number exceeds current system available range.\r\n",
                FOREGROUND_RED | FOREGROUND_INTENSITY);
            return;

        }

    }

    FuzzRun(Context);

    FreeLibrary((HMODULE)Context->SystemImageBase);

    ConsoleShowMessage("[-] Leaving FuzzInitPhase2()\r\n",
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
    _In_ NTCALL_FUZZ_PARAMS* FuzzParams
)
{
    BOOLEAN bWasEnabled = FALSE;
    WORD wColor = 0;
    UINT i;

    BOOL LogEnabled = FALSE;
    CHAR szOut[MAX_PATH * 2];
    RTL_OSVERSIONINFOW osver;


    ConsoleShowMessage("[+] Entering FuzzInitPhase1()\r\n",
        FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);

    g_ctx.ThreadWaitTimeout = FuzzParams->ThreadWaitTimeout;

    if (g_ctx.IsLocalSystem)
        ConsoleShowMessage("[+] LocalSystem account\r\n", 0);

    if (g_ctx.IsUserInAdminGroup) {
        ConsoleShowMessage("[+] User is admin\r\n", 0);

        if (g_ctx.IsElevated) {
            ConsoleShowMessage("[+] NtCall64 runs elevated.\r\n", 0);
        }
        else {
            ConsoleShowMessage("[+] NtCall64 is not elevated, some privileges can not be adjusted.\r\n", 0);
        }
    }

    RtlSecureZeroMemory(g_ctx.szSystemDirectory, sizeof(g_ctx.szSystemDirectory));
    if (!GetSystemDirectory(g_ctx.szSystemDirectory, MAX_PATH)) {
        ConsoleShowMessage("[!] Could not query system directory, abort!\r\n",
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
    ConsoleShowMessage(szOut, 0);

    //
    // Show command line.
    //
    ConsoleShowMessage("[+] Command line -> \r\n\r\n", 0);
    ConsoleShowMessage(GetCommandLineA(), 0);
    ConsoleShowMessage("\r\n\r\n", 0);

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
    ConsoleShowMessage(szOut, 0);

    if (FuzzParams->EnableLog) {

        g_Log.LogHandle = INVALID_HANDLE_VALUE;
        g_Log.LogToFile = FuzzParams->LogToFile;

        LogEnabled = FuzzOpenLog(FuzzParams->szLogDeviceOrFile, &g_Log);
        if (!LogEnabled) {

            _strcpy_a(szOut, "[!] Log open error, GetLastError() = ");
            ultostr_a(GetLastError(), _strend_a(szOut));
            _strcat_a(szOut, ", logging is disabled\r\n");

            ConsoleShowMessage(szOut, FOREGROUND_RED | FOREGROUND_INTENSITY);

        }
        else
            ConsoleShowMessage("[+] Logging is enabled\r\n",
                FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);

        g_ctx.LogEnabled = LogEnabled;

    }
    else {
        g_ctx.LogEnabled = FALSE;
    }

    //
    // Handle single system call.
    //
    if (FuzzParams->ProbeSingleSyscall) {
        g_ctx.ProbeWin32k = (FuzzParams->SingleSyscallId >= W32SYSCALLSTART);
        g_ctx.ProbeSingleSyscall = TRUE;
        g_ctx.SingleSyscallId = FuzzParams->SingleSyscallId;
    }
    else {
        g_ctx.ProbeWin32k = FuzzParams->ProbeWin32k;
    }

    //
    // Remember pass count.
    //
    g_ctx.SyscallPassCount = FuzzParams->SyscallPassCount;
    _strcpy_a(szOut, "[+] Number of passes for each syscall = ");
    u64tostr_a(g_ctx.SyscallPassCount, _strend_a(szOut));
    _strcat_a(szOut, "\r\n");
    ConsoleShowMessage(szOut, 0);

    //
    // Show wait timeout.
    //
    _strcpy_a(szOut, "[+] Wait timeout for caller threads (seconds) = ");
    ultostr_a(g_ctx.ThreadWaitTimeout, _strend_a(szOut));
    _strcat_a(szOut, "\r\n");
    ConsoleShowMessage(szOut, 0);

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
        ConsoleShowMessage(szOut, wColor);
    }

    if (g_ctx.ProbeWin32k) {

        ConsoleShowMessage("[*] Win32k table probe mode.\r\n",
            FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        Sleep(1000);

        BlackListCreateFromFile(&g_ctx.BlackList, CFG_FILE, (LPCSTR)"win32k");
    }
    else {

        ConsoleShowMessage("[*] Ntoskrnl table probe mode.\r\n",
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
        ConsoleShowMessage("[-] Logging stop\r\n", 0);
        FuzzCloseLog(&g_Log);
    }

    if (g_ctx.Win32pServiceTableNames)
        HeapFree(GetProcessHeap(), 0, g_ctx.Win32pServiceTableNames);

    ConsoleShowMessage("[-] Leaving FuzzInitPhase1()\r\n",
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
    ULONG rLen;
    NTCALL_FUZZ_PARAMS fuzzParams;

    TCHAR szTextBuf[MAX_PATH + 1];

    do {

        ConsoleShowMessage("[+] Entering FuzzInitPhase0()\r\n",
            FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);

        RtlSecureZeroMemory(&fuzzParams, sizeof(fuzzParams));
        fuzzParams.ThreadWaitTimeout = FUZZ_THREAD_TIMEOUT_SEC;
        fuzzParams.SyscallPassCount = FUZZ_PASS_COUNT;

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

        if (GetCommandLineOption(PARAM_LOCALSYSTEM, FALSE, NULL, 0, NULL)) {
            if (g_ctx.IsLocalSystem == FALSE) {
                if (g_ctx.IsUserInAdminGroup == FALSE) {
                    ConsoleShowMessage("[~] Administrative privileges reqruied for this operation\r\n", 0);
                    break;
                }
                if (g_ctx.IsElevated == FALSE) {
                    ConsoleShowMessage("[~] Elevation required to start as LocalSystem\r\n", 0);
                    break;
                }
                ConsoleShowMessage("[~] Restarting as LocalSystem\r\n", 0);
                RunAsLocalSystem();
                break;
            }
            //
            // Already LocalSystem, skip.
            //
        }

        fuzzParams.ProbeWin32k = GetCommandLineOption(PARAM_WIN32K, FALSE, NULL, 0, NULL);
        fuzzParams.EnableLog = GetCommandLineOption(PARAM_LOG, FALSE, NULL, 0, NULL);
        if (fuzzParams.EnableLog) {

            _strcpy(fuzzParams.szLogDeviceOrFile, DEFAULT_LOG_PORT);
            fuzzParams.LogToFile = FALSE;

            //
            // Check log port name.
            //
            rLen = 0;
            RtlSecureZeroMemory(szTextBuf, sizeof(szTextBuf));
            if (GetCommandLineOption(PARAM_LOGPORT, TRUE, szTextBuf, sizeof(szTextBuf) / sizeof(TCHAR), &rLen)) {
                if (rLen) {
                    _strcpy(fuzzParams.szLogDeviceOrFile, szTextBuf);
                }
                fuzzParams.LogToFile = FALSE;
            }
            else {

                //
                // Check log file name.
                //
                rLen = 0;
                RtlSecureZeroMemory(szTextBuf, sizeof(szTextBuf));
                if (GetCommandLineOption(PARAM_LOGFILE, TRUE, szTextBuf, sizeof(szTextBuf) / sizeof(TCHAR), &rLen)) {
                    if (rLen) {
                        _strcpy(fuzzParams.szLogDeviceOrFile, szTextBuf);
                    }
                    else {
                        _strcpy(fuzzParams.szLogDeviceOrFile, DEFAULT_LOG_FILE);
                    }
                    fuzzParams.LogToFile = TRUE;
                }

            }
        }

        RtlSecureZeroMemory(szTextBuf, sizeof(szTextBuf));
        if (GetCommandLineOption(PARAM_SYSCALL, TRUE, szTextBuf, sizeof(szTextBuf) / sizeof(TCHAR), NULL))
        {
            fuzzParams.ProbeSingleSyscall = TRUE;
            fuzzParams.SingleSyscallId = _strtoul(szTextBuf);
        }

        RtlSecureZeroMemory(szTextBuf, sizeof(szTextBuf));
        if (GetCommandLineOption(PARAM_PASSCOUNT, TRUE, szTextBuf, sizeof(szTextBuf) / sizeof(TCHAR), NULL))
        {
            fuzzParams.SyscallPassCount = strtou64(szTextBuf);
        }

        if (fuzzParams.SyscallPassCount == 0)
            fuzzParams.SyscallPassCount = FUZZ_PASS_COUNT;

        if (fuzzParams.ProbeSingleSyscall && fuzzParams.ProbeWin32k) {
            ConsoleShowMessage("Invalid combination of command line arguments.\r\n", 0);
            break;
        }

        RtlSecureZeroMemory(szTextBuf, sizeof(szTextBuf));
        if (GetCommandLineOption(PARAM_WAITTIMEOUT, TRUE, szTextBuf, sizeof(szTextBuf) / sizeof(TCHAR), NULL))
        {
            fuzzParams.ThreadWaitTimeout = _strtoul(szTextBuf);
        }

        if (fuzzParams.ThreadWaitTimeout == 0)
            fuzzParams.ThreadWaitTimeout = FUZZ_THREAD_TIMEOUT_SEC;

        FuzzInitPhase1(&fuzzParams);

    } while (FALSE);

    ConsoleShowMessage("[-] Leaving FuzzInitPhase0()\r\n",
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

    ConsoleInit();
    ConsoleShowMessage(WELCOME_BANNER, 0);
    ConsoleShowMessage(VERSION_BANNER, 0);

    ExceptionHandler = RtlAddVectoredExceptionHandler(1, &VehHandler);
    if (ExceptionHandler) {

        do {

            if (GetCommandLineOption(PARAM_HELP, FALSE, NULL, 0, NULL)) {
                ConsoleShowMessage(T_HELP, 0);
                break;
            }

            FuzzInitPhase0();
            ConsoleShowMessage("Bye!\r\n", 0);

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
