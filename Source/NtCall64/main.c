/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2026
*
*  TITLE:       MAIN.C
*
*  VERSION:     2.01
*
*  DATE:        14 Feb 2026
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

#define PARAM_HELP          TEXT("-help")
#define PARAM_LOG           TEXT("-log")
#define PARAM_OUTPUT        TEXT("-o")
#define PARAM_WIN32K        TEXT("-win32k")
#define PARAM_SYSCALL       TEXT("-call")
#define PARAM_PASSCOUNT     TEXT("-pc")
#define PARAM_WAITTIMEOUT   TEXT("-wt")
#define PARAM_SYSCALL_START TEXT("-sc")
#define PARAM_HEUR          TEXT("-h")
#define PARAM_LOCALSYSTEM   TEXT("-s")

#define DEFAULT_LOG_PORT    TEXT("COM1")
#define DEFAULT_LOG_FILE    TEXT("ntcall64.log")

#define WELCOME_BANNER      "Windows NT x64 syscall fuzzer, based on NtCall by Peter Kosyh."
#define VERSION_BANNER      "Version 2.0.1 from 14 Feb 2026\r\n"
#define PSEUDO_GRAPHICS_BANNER "\
 _   _ _____ _____   ___   _      _       ____    ___ \n\
| \\ | |_   _/  __ \\ / _ \\ | |    | |     / ___|  /   |\n\
|  \\| | | | | /  \\// /_\\ \\| |    | |    / /___  / /| |\n\
| . ` | | | | |    |  _  || |    | |    | ___ \\/ /_| |\n\
| |\\  | | | | \\__/\\| | | || |____| |____| \\_/ |\\___  |\n\
\\_| \\_/ \\_/  \\____/\\_| |_/\\_____/\\_____/\\_____/    |_/\n\
                                                      \n"

//
// Help output.
//
#define T_HELP	"Usage: -help [-win32k][-log [-o <file_or_port>]][-call Id][-pc Value][-wt Value][-s][-h]\r\n\
  -help     - Show this help information\r\n\
  -log      - Enable logging to file last call parameters (warning: this will drop performance)\r\n\
  -o Value  - Output log destination (port name like COM1, COM2... or file name), default ntcall64.log (-log required)\r\n\
  -win32k   - Fuzz win32k graphical subsystem table, otherwise fuzz ntos table\r\n\
  -call Id  - Fuzz syscall by supplied numeric <Id> (can be from any table). All blacklists are ignored\r\n\
  -pc Value - Set number of passes for each service to <Value>, default value 65536\r\n\
  -wt Value - Set wait timeout for calling threads in seconds (except single syscall fuzzing), default value is 30\r\n\
  -sc Value - Start fuzzing from service entry number (index from 0), default 0\r\n\
  -h        - Enable heuristics when building syscall parameters\r\n\
  -s        - Attempt to run program from LocalSystem account\r\n\n\
Example: ntcall64.exe -win32k -log -o COM2"

//
// Global context.
//
NTCALL_CONTEXT g_ctx;
NTCALL_LOG_PARAMS g_Log;

DWORD g_privs[] = {
    SE_CREATE_TOKEN_PRIVILEGE, 
    SE_ASSIGNPRIMARYTOKEN_PRIVILEGE,
    SE_LOCK_MEMORY_PRIVILEGE,
    SE_INCREASE_QUOTA_PRIVILEGE,
    SE_MACHINE_ACCOUNT_PRIVILEGE,
    SE_TCB_PRIVILEGE,
    SE_SECURITY_PRIVILEGE, 
    SE_TAKE_OWNERSHIP_PRIVILEGE,
    SE_LOAD_DRIVER_PRIVILEGE,
    SE_SYSTEM_PROFILE_PRIVILEGE,
    SE_SYSTEMTIME_PRIVILEGE,
    SE_PROF_SINGLE_PROCESS_PRIVILEGE,
    SE_INC_BASE_PRIORITY_PRIVILEGE,
    SE_CREATE_PAGEFILE_PRIVILEGE,
    SE_CREATE_PERMANENT_PRIVILEGE,
    SE_BACKUP_PRIVILEGE,
    SE_RESTORE_PRIVILEGE,
    SE_SHUTDOWN_PRIVILEGE,
    SE_DEBUG_PRIVILEGE,
    SE_AUDIT_PRIVILEGE,
    SE_SYSTEM_ENVIRONMENT_PRIVILEGE,
    SE_CHANGE_NOTIFY_PRIVILEGE,
    SE_REMOTE_SHUTDOWN_PRIVILEGE,
    SE_UNDOCK_PRIVILEGE,
    SE_SYNC_AGENT_PRIVILEGE,
    SE_ENABLE_DELEGATION_PRIVILEGE,
    SE_MANAGE_VOLUME_PRIVILEGE,
    SE_IMPERSONATE_PRIVILEGE,
    SE_CREATE_GLOBAL_PRIVILEGE,
    SE_TRUSTED_CREDMAN_ACCESS_PRIVILEGE,
    SE_RELABEL_PRIVILEGE,
    SE_INC_WORKING_SET_PRIVILEGE,
    SE_TIME_ZONE_PRIVILEGE,
    SE_CREATE_SYMBOLIC_LINK_PRIVILEGE
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
    DWORD64 ExitThreadPfn;
    HMODULE hModule = GetModuleHandle(TEXT("kernel32.dll"));
    if (hModule) {
        ExitThreadPfn = (DWORD64)GetProcAddress(hModule, "ExitThread");
        if (ExitThreadPfn)
            ExceptionInfo->ContextRecord->Rip = ExitThreadPfn;
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
UINT FuzzInitPhase2(
    _In_ NTCALL_CONTEXT* Context
)
{
    BOOL probeWin32k;
    UINT result = ERROR_SUCCESS;
    ULONG syscallEffectiveId;

    NTSTATUS ntStatus;
    UNICODE_STRING usModule;

    WCHAR szBuffer[MAX_PATH * 2];

    ConsoleShowMessage("[+] Entering FuzzInitPhase2()", TEXT_COLOR_CYAN);
    probeWin32k = Context->ProbeWin32k;
    StringCchPrintf(szBuffer, ARRAYSIZE(szBuffer), L"\\systemroot\\system32\\%ws",
        (probeWin32k) ? TEXT("win32k.sys") : TEXT("ntoskrnl.exe"));

    RtlInitUnicodeString(&usModule, szBuffer);
    ntStatus = supMapImageNoExecute(&usModule, &Context->SystemModuleBase);

    if (!NT_SUCCESS(ntStatus) || (Context->SystemModuleBase == NULL)) {
        supShowNtStatus("[!] Could not preload system image, abort!", ntStatus);
        return (UINT)-4;
    }

    if (probeWin32k) {
        if (!supFindW32pServiceTable(Context->SystemModuleBase, &Context->ServiceTable)) {
            ConsoleShowMessage("[!] Could not find W32pServiceTable, abort!", TEXT_COLOR_RED);
            result = (UINT)-5;
        }
        if (!FuzzLookupWin32kNames(Context)) {
            ConsoleShowMessage("[!] Win32k names query error, abort!", TEXT_COLOR_RED);
            result = (UINT)-6;
        }
    }
    else {
        Context->NtdllBase = (PVOID)GetModuleHandle(TEXT("ntdll.dll"));
        if (Context->NtdllBase == NULL) {
            ConsoleShowMessage("[!] NTDLL not found, abort!", TEXT_COLOR_RED);
            result = (UINT)-7;
        }
        if (!supFindKiServiceTable(Context->SystemModuleBase, &Context->ServiceTable)) {
            ConsoleShowMessage("[!] KiServiceTable not found, abort!", TEXT_COLOR_RED);
            result = (UINT)-8;
        }
    }

    if (result == ERROR_SUCCESS) {
        //
        // Validate syscall id.
        //
        if (Context->ProbeSingleSyscall) {
            syscallEffectiveId = Context->u1.SingleSyscallId;
            if (Context->ProbeWin32k) {
                syscallEffectiveId -= W32SYSCALLSTART;
            }
            if (syscallEffectiveId >= Context->ServiceTable.CountOfEntries) {
                ConsoleShowMessage("[!] Syscall number exceeds current system available range.", TEXT_COLOR_RED);
                result = (UINT)-9;
            }
        }
        if (result == ERROR_SUCCESS)
            FuzzRun(Context);
    }

    NtUnmapViewOfSection(NtCurrentProcess(), Context->SystemModuleBase);
    ConsoleShowMessage("[-] Leaving FuzzInitPhase2()", TEXT_COLOR_CYAN);

    return result;
}

/*
* FuzzInitPhase1
*
* Purpose:
*
* Initial preparations for probing.
*
*/
UINT FuzzInitPhase1(
    _In_ NTCALL_FUZZ_PARAMS* FuzzParams
)
{
    UINT enabled = 0, result = 0;
    BOOLEAN LogEnabled = FALSE;
    BOOLEAN bWasEnabled = FALSE;
    UINT i;

    CHAR szOut[2048];
    CHAR szCurrentDir[MAX_PATH + 1];

    ConsoleShowMessage("[+] Entering FuzzInitPhase1()", TEXT_COLOR_CYAN);

    g_ctx.ThreadWaitTimeout = FuzzParams->ThreadWaitTimeout;
    g_ctx.EnableParamsHeuristic = FuzzParams->EnableParamsHeuristic;
    g_ctx.SyscallPassCount = FuzzParams->SyscallPassCount;

    if (g_ctx.IsLocalSystem)
        ConsoleShowMessage("[+] LocalSystem account", TEXT_COLOR_CYAN);

    if (g_ctx.IsUserFullAdmin) {
        ConsoleShowMessage("[+] User is with admin privileges", TEXT_COLOR_CYAN);

        if (g_ctx.IsElevated) {
            ConsoleShowMessage("[+] NtCall64 runs elevated", TEXT_COLOR_CYAN);
        }
        else {
            ConsoleShowMessage("[+] NtCall64 is not elevated, some privileges can not be adjusted", TEXT_COLOR_RED);
        }
    }

    RtlZeroMemory(szOut, sizeof(szOut));
    RtlZeroMemory(szCurrentDir, sizeof(szCurrentDir));

    g_ctx.OsVersion.dwOSVersionInfoSize = sizeof(g_ctx.OsVersion);
    RtlGetVersion(&g_ctx.OsVersion);
    StringCchPrintfA(szOut, ARRAYSIZE(szOut), "[+] Windows version: %lu.%lu.%lu",
        g_ctx.OsVersion.dwMajorVersion,
        g_ctx.OsVersion.dwMinorVersion,
        g_ctx.OsVersion.dwBuildNumber);
    ConsoleShowMessage(szOut, TEXT_COLOR_CYAN);

    GetCurrentDirectoryA(MAX_PATH, szCurrentDir);
    StringCchPrintfA(szOut, ARRAYSIZE(szOut), "[~] Base configuration\nCurrent directory: %s\nCommand line: %s\n"\
        "Pass count: %llu per each syscall\n"\
        "Thread timeout: %lu sec\nParam heuristics: %s", 
        szCurrentDir,
        GetCommandLineA(),
        g_ctx.SyscallPassCount,
        g_ctx.ThreadWaitTimeout,
        g_ctx.EnableParamsHeuristic ? "Enabled" : "Disabled");

    ConsoleShowMessage(szOut, 0);

    if (FuzzParams->LogEnabled) {

        g_Log.LogHandle = INVALID_HANDLE_VALUE;
        g_Log.LogToFile = FuzzParams->LogToFile;

        LogEnabled = FuzzOpenLog(FuzzParams->szLogDeviceOrFile, &g_Log);
        if (!LogEnabled) {
            StringCchPrintfA(szOut, ARRAYSIZE(szOut), "[!] Log open error, GetLastError() = %lu, log will be disabled", GetLastError());
            ConsoleShowMessage(szOut, TEXT_COLOR_RED);
        }
        else {
            _strcpy_a(szOut, "[+] Logging is enabled, output will be written to ");
            WideCharToMultiByte(CP_ACP, 0, FuzzParams->szLogDeviceOrFile, -1,
                _strend_a(szOut), MAX_PATH, NULL, NULL);
            ConsoleShowMessage(szOut, TEXT_COLOR_CYAN);
        }

        g_ctx.LogEnabled = LogEnabled;

    }
    else {
        g_ctx.LogEnabled = FALSE;
    }

    // Handle single system call
    if (FuzzParams->ProbeSingleSyscall) {
        g_ctx.ProbeWin32k = (FuzzParams->u1.SingleSyscallId >= W32SYSCALLSTART);
        g_ctx.ProbeSingleSyscall = TRUE;
        g_ctx.u1.SingleSyscallId = FuzzParams->u1.SingleSyscallId;
    }
    else {
        g_ctx.ProbeWin32k = FuzzParams->ProbeWin32k;
    }

    // Show probe from syscall id
    g_ctx.ProbeFromSyscallId = FuzzParams->ProbeFromSyscallId;
    g_ctx.u1.StartingSyscallId = FuzzParams->u1.StartingSyscallId;
    if (g_ctx.ProbeFromSyscallId) {
        if (g_ctx.u1.StartingSyscallId >= W32SYSCALLSTART)
            g_ctx.ProbeWin32k = TRUE; // Force flag
        StringCchPrintfA(szOut, ARRAYSIZE(szOut), "[+] Starting syscall id %lu", g_ctx.u1.StartingSyscallId);
        ConsoleShowMessage(szOut, TEXT_COLOR_CYAN);
    }

    // Assign as much privileges as we can.
    enabled = 0;
    for (i = 0; i < _countof(g_privs); i++) {
        if (NT_SUCCESS(RtlAdjustPrivilege(g_privs[i], TRUE, FALSE, &bWasEnabled)))
            enabled++;
    }
    // Warn if less than half of requested privileges could be enabled.
    // This is not usually critical for normal user runs, but may indicate
    // unusual restrictions or a non-admin context.
    if (enabled < (_countof(g_privs) / 2)) {
        StringCchPrintfA(szOut, ARRAYSIZE(szOut),
            "[~] Warning: Only a minority of privileges were enabled (%lu/%llu)", 
            enabled, _countof(g_privs));
        ConsoleShowMessage(szOut, TEXT_COLOR_YELLOW);
    }

    ConsoleShowMessage(g_ctx.ProbeWin32k ? "[*] Win32k table probe mode" : "[*] Ntoskrnl table probe mode", TEXT_COLOR_CYAN);

    if (BlackListCreateFromFile(&g_ctx.BlackList, CFG_FILE, g_ctx.ProbeWin32k ? (LPCSTR)"win32k" : (LPCSTR)"ntos")) {
        StringCchPrintfA(szOut, ARRAYSIZE(szOut), "[+] Blacklist created with %lu entries", g_ctx.BlackList.NumberOfEntries);
        ConsoleShowMessage(szOut, TEXT_COLOR_CYAN);
    }

    result = FuzzInitPhase2(&g_ctx);

    //
    // Cleanup.
    //
    BlackListDestroy(&g_ctx.BlackList);

    if (LogEnabled) {
        ConsoleShowMessage("[-] Logging stop", TEXT_COLOR_CYAN);
        FuzzCloseLog(&g_Log);
    }

    if (g_ctx.Win32pServiceTableNames)
        supHeapFree(g_ctx.Win32pServiceTableNames);

    if (g_ctx.Win32ShadowTable)
        supFreeWin32ShadowTable(g_ctx.Win32ShadowTable);

    ConsoleShowMessage("[-] Leaving FuzzInitPhase1()", TEXT_COLOR_CYAN);

    return result;
}

/*
* FuzzInitPhase0
*
* Purpose:
*
* Parse command line options.
*
*/
UINT FuzzInitPhase0(
    VOID
)
{
    UINT result = 0;
    ULONG rLen;
    NTCALL_FUZZ_PARAMS fuzzParams;
    HANDLE hToken;
    NTSTATUS ntStatus;
    LPWSTR commandLine = GetCommandLine();

    WCHAR szTextBuf[MAX_PATH + 1];

    do {
        ConsoleShowMessage("[+] Entering FuzzInitPhase0()", TEXT_COLOR_CYAN);

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
                supShowNtStatus("[!] Failed to query process token information", ntStatus);
                return (UINT)-2;
            }

            NtClose(hToken);
        }
        else {
            supShowNtStatus("[!] Failed to open self process token", ntStatus);
            return (UINT)-3;
        }

        // -s (System) param.   
        if (supGetParamOption(commandLine, PARAM_LOCALSYSTEM, FALSE, NULL, 0, NULL)) {
            if (g_ctx.IsLocalSystem == FALSE) {
                if (g_ctx.IsUserFullAdmin == FALSE) {
                    ConsoleShowMessage("[~] Administrative privileges are required for this operation", 0);
                    break;
                }
                if (g_ctx.IsElevated == FALSE) {
                    ConsoleShowMessage("[~] Elevation required to start as LocalSystem", 0);
                    break;
                }
                ConsoleShowMessage("[~] Restarting as LocalSystem", 0);
                supRunAsLocalSystem();
                break;
            }
            // Already LocalSystem, skip.
        }

        // -win32k param.
        fuzzParams.ProbeWin32k = supGetParamOption(commandLine, PARAM_WIN32K, FALSE, NULL, 0, NULL);

        // -log param.
        fuzzParams.LogEnabled = supGetParamOption(commandLine, PARAM_LOG, FALSE, NULL, 0, NULL);
        if (fuzzParams.LogEnabled) {
            rLen = 0;
            RtlSecureZeroMemory(szTextBuf, sizeof(szTextBuf));
            if (supGetParamOption(commandLine, 
                PARAM_OUTPUT, 
                TRUE, 
                szTextBuf, 
                RTL_NUMBER_OF(szTextBuf), 
                &rLen) && rLen) 
            {
                _strcpy(fuzzParams.szLogDeviceOrFile, szTextBuf);
            }
            else {
                _strcpy(fuzzParams.szLogDeviceOrFile, DEFAULT_LOG_FILE);
            }

            if (supIsComPort(fuzzParams.szLogDeviceOrFile)) {
                fuzzParams.LogToFile = FALSE;
            }
            else {
                fuzzParams.LogToFile = TRUE;
            }

        }

        // -call (SyscallId) param.
        rLen = 0;
        RtlSecureZeroMemory(szTextBuf, sizeof(szTextBuf));
        if (supGetParamOption(commandLine, 
            PARAM_SYSCALL,
            TRUE, 
            szTextBuf, 
            RTL_NUMBER_OF(szTextBuf), 
            &rLen) && rLen)
        {
            fuzzParams.ProbeSingleSyscall = TRUE;
            fuzzParams.u1.SingleSyscallId = _strtoul(szTextBuf);
        }

        if (fuzzParams.ProbeSingleSyscall == FALSE) {
            // -start (SyscallId) param.
            rLen = 0;
            RtlSecureZeroMemory(szTextBuf, sizeof(szTextBuf));
            if (supGetParamOption(commandLine, 
                PARAM_SYSCALL_START,
                TRUE,
                szTextBuf,
                RTL_NUMBER_OF(szTextBuf),
                &rLen) && rLen)
            {
                fuzzParams.ProbeFromSyscallId = TRUE;
                fuzzParams.u1.StartingSyscallId = _strtoul(szTextBuf);
            }
        }

        // -pc (PassCount) param.
        rLen = 0;
        RtlSecureZeroMemory(szTextBuf, sizeof(szTextBuf));
        if (supGetParamOption(commandLine, 
            PARAM_PASSCOUNT,
            TRUE, 
            szTextBuf, 
            RTL_NUMBER_OF(szTextBuf), 
            &rLen) && rLen)
        {
            fuzzParams.SyscallPassCount = strtou64(szTextBuf);
        }

        if (fuzzParams.SyscallPassCount == 0)
            fuzzParams.SyscallPassCount = FUZZ_PASS_COUNT;

        if (fuzzParams.ProbeSingleSyscall && fuzzParams.ProbeWin32k) {
            ConsoleShowMessage("Invalid combination of command line arguments.", 0);
            break;
        }

        // -wt (WaitTimeout) param.
        RtlSecureZeroMemory(szTextBuf, sizeof(szTextBuf));
        if (supGetParamOption(commandLine, 
            PARAM_WAITTIMEOUT,
            TRUE, 
            szTextBuf, 
            RTL_NUMBER_OF(szTextBuf),
            &rLen) && rLen)
        {
            fuzzParams.ThreadWaitTimeout = _strtoul(szTextBuf);
        }

        if (fuzzParams.ThreadWaitTimeout == 0)
            fuzzParams.ThreadWaitTimeout = FUZZ_THREAD_TIMEOUT_SEC;

        //
        // -h (Heuristics) param.
        //
        if (supGetParamOption(commandLine, PARAM_HEUR, FALSE, NULL, 0, NULL)) {
            fuzzParams.EnableParamsHeuristic = TRUE;
        }

        result = FuzzInitPhase1(&fuzzParams);

    } while (FALSE);

    ConsoleShowMessage("[-] Leaving FuzzInitPhase0()", TEXT_COLOR_CYAN);

    return result;
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
    UINT result = 0;
    PVOID ExceptionHandler;

    if (!ConsoleInit())
        return (UINT)-1;

    ConsoleShowMessage(PSEUDO_GRAPHICS_BANNER, TEXT_COLOR_CYAN);
    ConsoleShowMessage(WELCOME_BANNER, TEXT_COLOR_CYAN);
    ConsoleShowMessage(VERSION_BANNER, TEXT_COLOR_CYAN);

#ifdef _DEBUG
    if (VerifySyscallDatabaseSorted(0))
        DbgPrint("KnownNtSyscalls OK\n");
    else
        DbgPrint("KnownNtSyscalls BAD\n");

    if (VerifySyscallDatabaseSorted(1))
        DbgPrint("KnownWin32kSyscalls OK\n");
    else 
        DbgPrint("KnownWin32kSyscalls BAD\n");

#endif

    ExceptionHandler = RtlAddVectoredExceptionHandler(1, &VehHandler);
    if (ExceptionHandler) {

        do {           
            if (supGetParamOption(GetCommandLine(), PARAM_HELP, FALSE, NULL, 0, NULL)) {
                ConsoleShowMessage(T_HELP, 0);
                break;
            }

            result = FuzzInitPhase0();
            ConsoleShowMessage("Bye!", 0);

        } while (FALSE);

        RtlRemoveVectoredExceptionHandler(ExceptionHandler);
    }

    return result;
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
