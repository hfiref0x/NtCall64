/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2025
*
*  TITLE:       FUZZ.C
*
*  VERSION:     2.00
*
*  DATE:        27 Jun 2025
*
*  Fuzzing routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

#ifdef __cplusplus 
extern "C" {
#endif
    NTSTATUS ntSyscallGate(ULONG ServiceId, ULONG ArgumentCount, ULONG_PTR* Arguments);
#ifdef __cplusplus
}
#endif

FUZZ_STATS g_FuzzStats = { 0 };


/*
* FuzzPrintServiceInformation
*
* Purpose:
*
* Display service information.
*
*/
void FuzzPrintServiceInformation(
    _In_ ULONG ServicesCount,
    _In_ ULONG NumberOfArguments,
    _In_ ULONG ServiceId,
    _In_opt_ LPCSTR ServiceName,
    _In_ BOOL BlackListed)
{
    CHAR szConsoleText[4096];
    WORD wColor = (BlackListed) ? FOREGROUND_GREEN | FOREGROUND_INTENSITY : 0;

    if (BlackListed) {
        StringCchPrintfA(szConsoleText, sizeof(szConsoleText),
            "\r[%04lu/%04lu] Service: %s, stack: %lu - found in blacklist, skipped",
            ServiceId,
            ServicesCount,
            ServiceName,
            NumberOfArguments);

        ConsoleShowMessage(szConsoleText, wColor);
    }
    else {

        StringCchPrintfA(szConsoleText, sizeof(szConsoleText),
            "\r[%04lu/%04lu] Service: %s, stack: %lu",
            ServiceId,
            ServicesCount,
            ServiceName,
            NumberOfArguments);

        ConsoleShowMessage2(szConsoleText, wColor);
    }
}

/*
* DoSystemCall
*
* Purpose:
*
* Fuzzing procedure, building parameters list and using syscall gate.
*
*/
NTSTATUS DoSystemCall(
    _In_ ULONG ServiceId,
    _In_ ULONG ParametersInStack,
    _In_ PVOID LogParams,
    _In_ LPCSTR ServiceName,
    _In_ BOOL EnableParamsHeuristic
)
{
    ULONG c, paramCount;
    ULONG_PTR args[MAX_PARAMETERS];
    PARAM_TYPE_HINT typeHints[MAX_PARAMETERS];
    NTSTATUS status;
    BOOL isWin32kSyscall = (ServiceId >= W32SYSCALLSTART);

    RtlSecureZeroMemory(args, sizeof(args));
    RtlSecureZeroMemory(typeHints, sizeof(typeHints));

    // Local thread buffer for parameters generation
    BYTE fuzzStructBuffer[MAX_STRUCT_BUFFER_SIZE] = { 0 };

    g_MemoryTracker.Count = 0;
    g_MemoryTracker.InUse = TRUE;

    paramCount = ParametersInStack / FUZZ_PARAMS_STACK_DIVISOR + FUZZ_EXTRA_PARAMS;

    if (EnableParamsHeuristic) {
        FuzzDetectParameterTypes(ServiceName, paramCount, isWin32kSyscall, typeHints);
    }

    for (c = 0; c < paramCount; c++) {
        args[c] = FuzzGenerateParameter(c, typeHints[c], isWin32kSyscall, 
            EnableParamsHeuristic, fuzzStructBuffer);
    }

    if (g_ctx.LogEnabled && LogParams) {
        FuzzLogCallBinary((PNTCALL_LOG_PARAMS)LogParams,
            ServiceId,
            paramCount,
            args);
    }

    status = ntSyscallGate(ServiceId, paramCount, args);

    InterlockedIncrement((PLONG)&g_FuzzStats.TotalCalls);

    if (NT_SUCCESS(status)) {
        InterlockedIncrement((PLONG)&g_FuzzStats.SuccessCalls);
    }
    else {
        InterlockedIncrement((PLONG)&g_FuzzStats.ErrorCalls);
    }

    return status;
}

/*
* FuzzLookupWin32kNames
*
* Purpose:
*
* Build shadow table service names list.
*
*/
BOOLEAN FuzzLookupWin32kNames(
    _Inout_ NTCALL_CONTEXT* Context
)
{
    ULONG i;
    PRAW_SERVICE_TABLE ServiceTable = &Context->ServiceTable;
    PCHAR* lpServiceNames;

    HMODULE win32u = NULL;
    ULONG win32uLimit;
    PWIN32_SHADOWTABLE ShadowTable = NULL;

    PCHAR serviceName;

    if (ServiceTable->CountOfEntries == 0 || ServiceTable->CountOfEntries > MAX_SYSCALL_COUNT)
        return FALSE;

    win32u = GetModuleHandle(WIN32U_DLL);
    if (win32u == NULL) {
        win32u = LoadLibrary(WIN32U_DLL);
        if (win32u == NULL) {
            ConsoleShowMessage("[!] Failed to load win32u.dll.", TEXT_COLOR_RED);
            return FALSE;
        }
    }

    lpServiceNames = (CHAR**)supHeapAlloc(ServiceTable->CountOfEntries * sizeof(PCHAR));
    if (lpServiceNames == NULL)
        return FALSE;

    win32uLimit = supEnumWin32uServices(GetProcessHeap(), (LPVOID)win32u, &ShadowTable);

    if (win32uLimit != ServiceTable->CountOfEntries || ShadowTable == NULL) {
        ConsoleShowMessage("[!] Win32u services enumeration failed.", TEXT_COLOR_RED);
        supHeapFree(lpServiceNames);
        return FALSE;
    }

    Context->Win32pServiceTableNames = lpServiceNames;

    for (i = 0; i < ServiceTable->CountOfEntries; i++) {
        serviceName = supResolveW32kServiceNameById(i + W32SYSCALLSTART, ShadowTable);
        lpServiceNames[i] = (serviceName != NULL) ? serviceName : "UnknownServiceName";
    }

    return TRUE;
}

/*
* FuzzThreadProc
*
* Purpose:
*
* Handler for fuzzing thread.
*
*/
DWORD WINAPI FuzzThreadProc(
    PVOID Parameter
)
{
    ULONG64 i, c;
    HMODULE hUser32 = NULL;
    CALL_PARAM* Context = (CALL_PARAM*)Parameter;
    LPCSTR serviceName = NULL;

    if (Context->Syscall >= W32SYSCALLSTART)
        hUser32 = LoadLibrary(TEXT("user32.dll"));

    c = Context->NumberOfPassesForCall;
    serviceName = (Context->ServiceName != NULL) ? Context->ServiceName : "UnknownServiceName";

    __try {
        for (i = 0; i < c; i++) {
            DoSystemCall(
                Context->Syscall,
                Context->ParametersInStack,
                Context->LogParams,
                serviceName,
                Context->EnableParamsHeuristic);

            FuzzCleanupAllocations();
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        FuzzCleanupAllocations();
        InterlockedIncrement((PLONG)&g_FuzzStats.CrashedCalls);
    }

    if (hUser32)
        FreeLibrary(hUser32);

    return 0;
}

/*
* FuzzRunThreadWithWait
*
* Purpose:
*
* Run fuzzing thread and wait with safer timeout handling.
*
*/
VOID FuzzRunThreadWithWait(
    _In_ CALL_PARAM* CallParams
)
{
    HANDLE hThread;
    DWORD dwThreadId, dwWaitResult;
    CHAR szConsoleText[100];

    hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)FuzzThreadProc,
        (LPVOID)CallParams, 0, &dwThreadId);

    if (hThread) {
        dwWaitResult = WaitForSingleObject(hThread, CallParams->ThreadTimeout);
        if (dwWaitResult == WAIT_TIMEOUT) {
            InterlockedIncrement((PLONG)&g_FuzzStats.TimeoutCalls);
            TerminateThread(hThread, (DWORD)-1);
            StringCchPrintfA(szConsoleText, sizeof(szConsoleText),
                "\r\n[~]Timeout reached for callproc of service: %s, callproc terminated.",
                CallParams->ServiceName);
            ConsoleShowMessage(szConsoleText, 0);
        }
        CloseHandle(hThread);
    }
}

/*
* FuzzRun
*
* Purpose:
*
* Perform syscall table fuzzing.
*
*/
VOID FuzzRun(
    _In_ NTCALL_CONTEXT* Context
)
{
    BOOL probeWin32k = Context->ProbeWin32k, bSkip = FALSE;
    BLACKLIST* BlackList = &Context->BlackList;
    PVOID ntdllBase = Context->NtdllBase;
    PRAW_SERVICE_TABLE ServiceTable = &Context->ServiceTable;
    ULONG syscallIndex, sid, nArgs;
    CALL_PARAM CallParams;
    PCHAR lpServiceName;
    CHAR szOut[MAX_PATH * 2];

    ConsoleShowMessage("[+] Entering FuzzRun()", TEXT_COLOR_CYAN);

    //
    // If single syscall mode, just call it.
    //
    if (Context->ProbeSingleSyscall) {

        //
        // Query service name.
        //
        if (probeWin32k) {
            sid = Context->u1.SingleSyscallId - W32SYSCALLSTART;
            lpServiceName = Context->Win32pServiceTableNames[sid];
        }
        else {
            sid = Context->u1.SingleSyscallId;
            lpServiceName = supGetProcNameBySDTIndex(ntdllBase, sid);
        }

        if (lpServiceName == NULL)
            lpServiceName = "UnknownServiceName";

        //
        // Output service information to console.
        //
        StringCchPrintfA(szOut, sizeof(szOut),
            "Probing #%lu\t\t%s",
            Context->u1.SingleSyscallId,
            lpServiceName);

        ConsoleShowMessage(szOut, 0);

        //
        // Setup service call parameters and call it in separate thread.
        //
        CallParams.ServiceName = lpServiceName;
        CallParams.ParametersInStack = Context->ServiceTable.StackArgumentTable[sid];
        CallParams.Syscall = Context->u1.SingleSyscallId;
        CallParams.ThreadTimeout = INFINITE;
        CallParams.NumberOfPassesForCall = Context->SyscallPassCount;
        CallParams.LogParams = &g_Log;
        CallParams.EnableParamsHeuristic = Context->EnableParamsHeuristic;

        FuzzRunThreadWithWait(&CallParams);
    }
    else {

        syscallIndex = 0;
        if (Context->ProbeFromSyscallId) {
            syscallIndex = Context->u1.StartingSyscallId;
            if (Context->ProbeWin32k)
                syscallIndex -= W32SYSCALLSTART;
        }

        for (; syscallIndex < ServiceTable->CountOfEntries; syscallIndex++) {

            //
            // Query service name.
            //
            if (probeWin32k) {
                lpServiceName = Context->Win32pServiceTableNames[syscallIndex];
                sid = W32SYSCALLSTART + syscallIndex;
            }
            else {
                lpServiceName = supGetProcNameBySDTIndex(ntdllBase, syscallIndex);
                sid = syscallIndex;
            }

            if (lpServiceName) {
                bSkip = BlackListEntryPresent(BlackList, (LPCSTR)lpServiceName);
            }
            else {
                lpServiceName = "UnknownServiceName";
            }

            //
            // Output service information to console.
            //
            nArgs = ServiceTable->StackArgumentTable[syscallIndex] / FUZZ_PARAMS_STACK_DIVISOR;
            FuzzPrintServiceInformation(
                ServiceTable->CountOfEntries,
                nArgs,
                (probeWin32k) ? sid - W32SYSCALLSTART : sid,
                lpServiceName,
                bSkip);

            if (bSkip) {
                bSkip = FALSE;
                continue;
            }
           
            //
            // Setup service call parameters and call it in separate thread.
            //
            CallParams.ServiceName = lpServiceName;
            CallParams.Syscall = sid;
            CallParams.ParametersInStack = Context->ServiceTable.StackArgumentTable[syscallIndex];
            CallParams.ThreadTimeout = (Context->ThreadWaitTimeout * 1000);
            CallParams.NumberOfPassesForCall = Context->SyscallPassCount;
            CallParams.LogParams = &g_Log;
            CallParams.EnableParamsHeuristic = Context->EnableParamsHeuristic;

            if (Context->LogEnabled)
                CallParams.ThreadTimeout *= FUZZ_TIMEOUT_MULTIPLE; //extend timeout with logging

            FuzzRunThreadWithWait(&CallParams);

        }
    }

    //
    // Print stats.
    // 
    StringCchPrintfA(szOut, sizeof(szOut), "\r----FuzzRun statistics----\r\n"\
        "Succeeded calls: %lu\r\n"\
        "Error calls: %lu\r\n"\
        "Crashed calls: %lu\r\n"\
        "Timed out calls: %lu\r\n"\
        "Total calls: %lu\r\n----FuzzRun statistics----\r\n",
        g_FuzzStats.SuccessCalls,
        g_FuzzStats.ErrorCalls,
        g_FuzzStats.CrashedCalls,
        g_FuzzStats.TimeoutCalls,
        g_FuzzStats.TotalCalls);

    ConsoleShowMessage2(szOut, 0);

    ConsoleShowMessage("[-] Leaving FuzzRun()", TEXT_COLOR_CYAN);
}
