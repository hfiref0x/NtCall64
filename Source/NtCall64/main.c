/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2023
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.37
*
*  DATE:        04 Aug 2023
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
#define PARAM_SYSCALL_START TEXT("-start")

#define DEFAULT_LOG_PORT    TEXT("COM1")
#define DEFAULT_LOG_FILE    TEXT("ntcall64.log")

#define WELCOME_BANNER      "NtCall64, Windows NT x64 syscall fuzzer, based on NtCall by Peter Kosyh.\r\n"
#define VERSION_BANNER      "Version 1.3.7 from 04 Aug 2023\r\n\n"

//
// Help output.
//
#define T_HELP	"Usage: -help [-win32k][-log [-pname][-ofile]][-call Id][-pc Value][-wt Value][-s]\r\n\
  -help     - Show this help information;\r\n\
  -log      - Enable logging to file last call parameters, use -ofile to specify file otherwise COM port will be used;\r\n\
  -pname    - Port name for logging, default COM1 (-log enabled required, mutual exclusive with -ofile);\r\n\
  -ofile    - File name for logging, default ntcall64.log (-log enabled required, mutual exclusive with -pname);\r\n\
  -win32k   - Fuzz win32k graphical subsystem table, otherwise fuzz ntos table;\r\n\
  -call Id  - Fuzz syscall by supplied numeric <Id> (can be from any table). All blacklists are ignored;\r\n\
  -pc Value - Set number of passes for each service to <Value>, default value 65536;\r\n\
  -wt Value - Set wait timeout for calling threads in seconds (except single syscall fuzzing), default value is 30;\r\n\
  -start Id - Fuzz syscall table starting from given syscall id, mutual exclusive with -call;\r\n\
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

    NTSTATUS ntStatus;
    UNICODE_STRING usModule;

    WCHAR szBuffer[MAX_PATH * 2];

    ConsoleShowMessage("[+] Entering FuzzInitPhase2()\r\n",
        FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);

    _strcpy(szBuffer, L"\\systemroot\\system32\\");
    if (probeWin32k) {
        _strcat(szBuffer, TEXT("win32k.sys"));
    }
    else {
        _strcat(szBuffer, TEXT("ntoskrnl.exe"));
    }

    RtlInitUnicodeString(&usModule, szBuffer);

    ntStatus = supMapImageNoExecute(&usModule, &Context->SystemModuleBase);

    if (!NT_SUCCESS(ntStatus) || (Context->SystemModuleBase == NULL)) {
        supShowNtStatus("[!] Could not preload system image, abort!\r\n", ntStatus);
        return;
    }

    if (probeWin32k) {

        if (!FuzzFindW32pServiceTable(Context->SystemModuleBase, &Context->ServiceTable)) {
            ConsoleShowMessage("[!] Could not find W32pServiceTable, abort!\r\n",
                FOREGROUND_RED | FOREGROUND_INTENSITY);
            return;
        }

        if (!FuzzLookupWin32kNames(Context)) {
            ConsoleShowMessage("[!] Win32k names query error, abort!\r\n",
                FOREGROUND_RED | FOREGROUND_INTENSITY);
            return;
        }
    }
    else {

        Context->NtdllBase = (PVOID)GetModuleHandle(TEXT("ntdll.dll"));
        if (Context->NtdllBase == NULL) {
            ConsoleShowMessage("[!] NTDLL not found, abort!\r\n",
                FOREGROUND_RED | FOREGROUND_INTENSITY);
            return;
        }

        if (!FuzzFindKiServiceTable(Context->SystemModuleBase, &Context->ServiceTable)) {
            ConsoleShowMessage("[!] KiServiceTable not found, abort!\r\n",
                FOREGROUND_RED | FOREGROUND_INTENSITY);
            return;
        }
    }

    //
    // Validate syscall id.
    //
    if (Context->ProbeSingleSyscall) {

        d = Context->u1.SingleSyscallId;

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

    NtUnmapViewOfSection(NtCurrentProcess(), Context->SystemModuleBase);

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
    BOOLEAN LogEnabled = FALSE;
    BOOLEAN bWasEnabled = FALSE;
    WORD wColor = 0;
    UINT i;

    CHAR szOut[MAX_PATH * 2];

    ConsoleShowMessage("[+] Entering FuzzInitPhase1()\r\n",
        FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);

    g_ctx.ThreadWaitTimeout = FuzzParams->ThreadWaitTimeout;

    if (g_ctx.IsLocalSystem)
        ConsoleShowMessage("[+] LocalSystem account\r\n", 0);

    if (g_ctx.IsUserFullAdmin) {
        ConsoleShowMessage("[+] User is with admin privileges\r\n", 0);

        if (g_ctx.IsElevated) {
            ConsoleShowMessage("[+] NtCall64 runs elevated.\r\n", 0);
        }
        else {
            ConsoleShowMessage("[+] NtCall64 is not elevated, some privileges can not be adjusted.\r\n", 0);
        }
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
    g_ctx.OsVersion.dwOSVersionInfoSize = sizeof(g_ctx.OsVersion);
    RtlGetVersion(&g_ctx.OsVersion);

    _strcpy_a(szOut, "[~] Windows version: ");
    ultostr_a(g_ctx.OsVersion.dwMajorVersion, _strend_a(szOut));
    ultostr_a(g_ctx.OsVersion.dwMinorVersion, _strcat_a(szOut, "."));
    ultostr_a(g_ctx.OsVersion.dwBuildNumber, _strcat_a(szOut, "."));
    _strcat_a(szOut, "\r\n");
    ConsoleShowMessage(szOut, 0);

    if (FuzzParams->LogEnabled) {

        g_Log.LogHandle = INVALID_HANDLE_VALUE;
        g_Log.LogToFile = FuzzParams->LogToFile;

        LogEnabled = FuzzOpenLog(FuzzParams->szLogDeviceOrFile, &g_Log);
        if (!LogEnabled) {

            _strcpy_a(szOut, "[!] Log open error, GetLastError() = ");
            ultostr_a(GetLastError(), _strend_a(szOut));
            _strcat_a(szOut, ", logging is disabled\r\n");

            ConsoleShowMessage(szOut, FOREGROUND_RED | FOREGROUND_INTENSITY);

        }
        else {
            _strcpy_a(szOut, "[+] Logging is enabled, output will be written to ");

            WideCharToMultiByte(CP_ACP, 0, FuzzParams->szLogDeviceOrFile, -1, 
                _strend_a(szOut), MAX_PATH, NULL, NULL);

            _strcat_a(szOut, "\r\n");
            
            ConsoleShowMessage(szOut,
                FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        }

        g_ctx.LogEnabled = LogEnabled;

    }
    else {
        g_ctx.LogEnabled = FALSE;
    }

    //
    // Handle single system call.
    //
    if (FuzzParams->ProbeSingleSyscall) {
        g_ctx.ProbeWin32k = (FuzzParams->u1.SingleSyscallId >= W32SYSCALLSTART);
        g_ctx.ProbeSingleSyscall = TRUE;
        g_ctx.u1.SingleSyscallId = FuzzParams->u1.SingleSyscallId;
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
    // Show probe from syscall id.
    //
    g_ctx.ProbeFromSyscallId = FuzzParams->ProbeFromSyscallId;
    g_ctx.u1.StartingSyscallId = FuzzParams->u1.StartingSyscallId;
    if (g_ctx.ProbeFromSyscallId) {
        _strcpy_a(szOut, "[+] Starting syscall id ");
        ultostr_a(g_ctx.u1.StartingSyscallId, _strend_a(szOut));
        _strcat_a(szOut, "\r\n");
        ConsoleShowMessage(szOut, 0);
    }

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
        supHeapFree(g_ctx.Win32pServiceTableNames);

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
    HANDLE hToken;
    NTSTATUS ntStatus;

    WCHAR szTextBuf[MAX_PATH + 1];

    do {

        ConsoleShowMessage("[+] Entering FuzzInitPhase0()\r\n",
            FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);

        RtlSecureZeroMemory(&fuzzParams, sizeof(fuzzParams));
        fuzzParams.ThreadWaitTimeout = FUZZ_THREAD_TIMEOUT_SEC;
        fuzzParams.SyscallPassCount = FUZZ_PASS_COUNT;

        RtlSecureZeroMemory(&g_ctx, sizeof(g_ctx));

        ntStatus = NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY, &hToken);
        if (NT_SUCCESS(ntStatus)) {

            ntStatus = supIsLocalSystem(hToken, &g_ctx.IsLocalSystem);
            if (NT_SUCCESS(ntStatus)) {
                if (g_ctx.IsLocalSystem) {
                    g_ctx.IsElevated = TRUE;
                    g_ctx.IsUserFullAdmin = TRUE;
                }
                else {
                    g_ctx.IsUserFullAdmin = supUserIsFullAdmin(hToken);
                    if (g_ctx.IsUserFullAdmin) {
                        g_ctx.IsElevated = supIsClientElevated(NtCurrentProcess());
                    }
                }
            }
            else {
                supShowNtStatus("[!] Failed to query process token information\r\n", ntStatus);
                return;
            }

            NtClose(hToken);
        }
        else {
            supShowNtStatus("[!] Failed to open self process token\r\n", ntStatus);
            return;
        }

        //
        // -s (System) param.
        //
        if (supGetCommandLineOption(PARAM_LOCALSYSTEM, FALSE, NULL, 0, NULL)) {
            if (g_ctx.IsLocalSystem == FALSE) {
                if (g_ctx.IsUserFullAdmin == FALSE) {
                    ConsoleShowMessage("[~] Administrative privileges are required for this operation\r\n", 0);
                    break;
                }
                if (g_ctx.IsElevated == FALSE) {
                    ConsoleShowMessage("[~] Elevation required to start as LocalSystem\r\n", 0);
                    break;
                }
                ConsoleShowMessage("[~] Restarting as LocalSystem\r\n", 0);
                supRunAsLocalSystem();
                break;
            }
            //
            // Already LocalSystem, skip.
            //
        }

        //
        // -win32k param.
        //
        fuzzParams.ProbeWin32k = supGetCommandLineOption(PARAM_WIN32K, FALSE, NULL, 0, NULL);

        //
        // -log param.
        //
        fuzzParams.LogEnabled = supGetCommandLineOption(PARAM_LOG, FALSE, NULL, 0, NULL);
        if (fuzzParams.LogEnabled) {

            _strcpy(fuzzParams.szLogDeviceOrFile, DEFAULT_LOG_PORT);
            fuzzParams.LogToFile = FALSE;

            //
            // Check log port name (-pname).
            //
            rLen = 0;
            RtlSecureZeroMemory(szTextBuf, sizeof(szTextBuf));
            if (supGetCommandLineOption(PARAM_LOGPORT,
                TRUE, 
                szTextBuf, 
                RTL_NUMBER_OF(szTextBuf), 
                &rLen)) 
            {
                if (rLen) {
                    _strcpy(fuzzParams.szLogDeviceOrFile, szTextBuf);
                }
            }
            else {

                //
                // Check log file name (-ofile).
                //
                rLen = 0;
                RtlSecureZeroMemory(szTextBuf, sizeof(szTextBuf));
                if (supGetCommandLineOption(PARAM_LOGFILE,
                    TRUE, 
                    szTextBuf, 
                    RTL_NUMBER_OF(szTextBuf),
                    &rLen)) 
                {
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

        //
        // -call (SyscallId) param.
        //
        RtlSecureZeroMemory(szTextBuf, sizeof(szTextBuf));
        if (supGetCommandLineOption(PARAM_SYSCALL,
            TRUE, 
            szTextBuf, 
            RTL_NUMBER_OF(szTextBuf), 
            NULL))
        {
            fuzzParams.ProbeSingleSyscall = TRUE;
            fuzzParams.u1.SingleSyscallId = _strtoul(szTextBuf);
        }

        if (fuzzParams.ProbeSingleSyscall == FALSE) {
            //
            // -start (SyscallId) param.
            //
            RtlSecureZeroMemory(szTextBuf, sizeof(szTextBuf));
            if (supGetCommandLineOption(PARAM_SYSCALL_START,
                TRUE,
                szTextBuf,
                RTL_NUMBER_OF(szTextBuf),
                NULL))
            {
                fuzzParams.ProbeFromSyscallId = TRUE;
                fuzzParams.u1.StartingSyscallId = _strtoul(szTextBuf);
            }
        }

        //
        // -pc (PassCount) param.
        //
        RtlSecureZeroMemory(szTextBuf, sizeof(szTextBuf));
        if (supGetCommandLineOption(PARAM_PASSCOUNT,
            TRUE, 
            szTextBuf, 
            RTL_NUMBER_OF(szTextBuf), 
            NULL))
        {
            fuzzParams.SyscallPassCount = strtou64(szTextBuf);
        }

        if (fuzzParams.SyscallPassCount == 0)
            fuzzParams.SyscallPassCount = FUZZ_PASS_COUNT;

        if (fuzzParams.ProbeSingleSyscall && fuzzParams.ProbeWin32k) {
            ConsoleShowMessage("Invalid combination of command line arguments.\r\n", 0);
            break;
        }

        //
        // -wt (WaitTimeout) param.
        //
        RtlSecureZeroMemory(szTextBuf, sizeof(szTextBuf));
        if (supGetCommandLineOption(PARAM_WAITTIMEOUT,
            TRUE, 
            szTextBuf, 
            RTL_NUMBER_OF(szTextBuf),
            NULL))
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

            if (supGetCommandLineOption(PARAM_HELP, FALSE, NULL, 0, NULL)) {
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
