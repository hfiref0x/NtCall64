/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2019
*
*  TITLE:       FUZZ.C
*
*  VERSION:     1.32
*
*  DATE:        20 July 2019
*
*  Fuzzing routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "main.h"
#include "tables.h"

#ifdef __cplusplus 
extern "C" {
#endif
    NTSTATUS ntSyscallGate(ULONG ServiceId, ULONG ArgumentCount, ULONG_PTR *Arguments);
#ifdef __cplusplus
}
#endif

/*
* DoSystemCall
*
* Purpose:
*
* Fuzzing procedure, building parameters list and using syscall gate.
*
*/
void DoSystemCall(
    _In_ ULONG ServiceId,
    _In_ ULONG ParametersInStack
)
{
    ULONG		c;
    ULONG_PTR	Arguments[MAX_PARAMETERS];
    ULONG64     u_rand;

    RtlSecureZeroMemory(Arguments, sizeof(Arguments));

    ParametersInStack /= 4;

    for (c = 0; c < ParametersInStack + 4; c++) {
        u_rand = __rdtsc();
        Arguments[c] = fuzzdata[u_rand % SIZEOF_FUZZDATA];
    }

    if (g_ctx.LogEnabled) {

        FuzzLogCallParameters(g_ctx.LogHandle,
            ServiceId,
            ParametersInStack + 4,
            (ULONG_PTR*)&Arguments);

    }

    ntSyscallGate(ServiceId, ParametersInStack + 4, Arguments);

}

/*
* FuzzLookupWin32kNames
*
* Purpose:
*
* Build shadow table service names list.
*
*/
BOOL FuzzLookupWin32kNames(
    _In_ LPWSTR ModuleName,
    _Inout_ NTCALL_CONTEXT *Context
)
{
    ULONG                   BuildNumber = 0, i;
    ULONG_PTR               MappedImageBase = Context->SystemImageBase;
    PIMAGE_NT_HEADERS       NtHeaders = RtlImageNtHeader((PVOID)MappedImageBase);
    PRAW_SERVICE_TABLE      ServiceTable = &Context->ServiceTable;
    ULONG_PTR	            Address;
    CHAR                  **Win32pServiceTableNames;

    DWORD64  *pW32pServiceTable = NULL;
    CHAR    **Names = NULL;
    PCHAR     pfn;

    IMAGE_IMPORT_BY_NAME *ImportEntry;

    HMODULE win32u = NULL;
    ULONG win32uLimit;
    PWIN32_SHADOWTABLE ShadowTable = NULL;

    PCHAR ServiceName;

    hde64s hs;

    if (!GetImageVersionInfo(ModuleName, NULL, NULL, &BuildNumber, NULL)) {
        FuzzShowMessage("[!] Failed to query win32k.sys version information.\r\n",
            FOREGROUND_RED | FOREGROUND_INTENSITY);
        return FALSE;
    }

    switch (BuildNumber) {

    case 7600:
    case 7601:
        if (ServiceTable->CountOfEntries != W32pServiceTableLimit_7601)
            return FALSE;
        Names = (CHAR**)W32pServiceTableNames_7601;
        break;

    case 9200:
        if (ServiceTable->CountOfEntries != W32pServiceTableLimit_9200)
            return FALSE;
        Names = (CHAR**)W32pServiceTableNames_9200;
        break;

    case 9600:
        if (ServiceTable->CountOfEntries != W32pServiceTableLimit_9600)
            return FALSE;
        Names = (CHAR**)W32pServiceTableNames_9600;
        break;

    default:
        break;
    }

    Win32pServiceTableNames = (CHAR**)HeapAlloc(GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        ServiceTable->CountOfEntries * sizeof(PVOID));

    if (Win32pServiceTableNames == NULL)
        return FALSE;

    Context->Win32pServiceTableNames = Win32pServiceTableNames;

    pW32pServiceTable = (DWORD64*)ServiceTable->ServiceTable;

    //
    // Query service names.
    // If win32k version below 10240 copy them from predefined array.
    // Otherwise lookup them dynamically.
    //
    if (BuildNumber < 10240) {
        if (Names == NULL)
            return FALSE;

        for (i = 0; i < ServiceTable->CountOfEntries; i++) {
            Win32pServiceTableNames[i] = Names[i];
        }
    }
    else {

        //
        // 
        //
        if (BuildNumber >= 14393) {

            win32u = LoadLibraryEx(TEXT("win32u.dll"), NULL, 0);
            if (win32u == NULL) {
                FuzzShowMessage("[!] Failed to load win32u.dll.\r\n",
                    FOREGROUND_RED | FOREGROUND_INTENSITY);
                return FALSE;
            }

            win32uLimit = FuzzEnumWin32uServices(GetProcessHeap(), (LPVOID)win32u, &ShadowTable);

            if ((win32uLimit != ServiceTable->CountOfEntries) || (ShadowTable == NULL)) {
                FuzzShowMessage("[!] Win32u services enumeration failed.\r\n",
                    FOREGROUND_RED | FOREGROUND_INTENSITY);
                return FALSE;
            }

        }

        for (i = 0; i < ServiceTable->CountOfEntries; i++) {

            ServiceName = "UnknownName";

            if (BuildNumber <= 10586) {
                pfn = (PCHAR)(pW32pServiceTable[i] - NtHeaders->OptionalHeader.ImageBase + MappedImageBase);
                hde64_disasm((void*)pfn, &hs);
                if (hs.flags & F_ERROR) {

                    FuzzShowMessage("[!]FuzzLookupWin32kNames HDE error.\r\n",
                        FOREGROUND_RED | FOREGROUND_INTENSITY);

                    break;
                }
                Address = MappedImageBase + *(ULONG_PTR*)(pfn + hs.len + *(DWORD*)(pfn + (hs.len - 4)));
                if (Address) {
                    ImportEntry = (IMAGE_IMPORT_BY_NAME *)Address;
                    ServiceName = ImportEntry->Name;
                }
            }
            else if (BuildNumber >= 14393) {

                ServiceName = FuzzResolveW32kServiceNameById(i + 0x1000, ShadowTable);
                if (ServiceName == NULL) ServiceName = "UnknownName";

            }
            Win32pServiceTableNames[i] = ServiceName;
        }
    }

    if (win32u) FreeLibrary(win32u);

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
    CALL_PARAM *Context = (CALL_PARAM*)Parameter;

    if (Context->Syscall >= W32SYSCALLSTART)
        hUser32 = LoadLibrary(TEXT("user32.dll"));

    c = Context->NumberOfPassesForCall;

    for (i = 0; i < c; i++) {
        DoSystemCall(Context->Syscall, Context->ParametersInStack);
    }

    if (hUser32)
        FreeLibrary(hUser32);

    ExitThread(0);
}

/*
* PrintServiceInformation
*
* Purpose:
*
* Display service information.
*
*/
void PrintServiceInformation(
    _In_ ULONG NumberOfArguments,
    _In_ ULONG ServiceId,
    _In_opt_ LPCSTR ServiceName,
    _In_ BOOL BlackListed)
{
    CHAR *pLog;
    CHAR szConsoleText[4096];
    WORD wColor = 0;

    _strcpy_a(szConsoleText, "\t#");
    ultostr_a(ServiceId, _strend_a(szConsoleText));

    pLog = _strcat_a(szConsoleText, "\tArgs(stack): ");
    ultostr_a(NumberOfArguments, pLog);

    pLog = _strcat_a(szConsoleText, "\t");
    if (ServiceName) {
        _strncpy_a(pLog, MAX_PATH, ServiceName, MAX_PATH);
    }
    else {
        _strcpy_a(pLog, "Unknown");
    }

    if (BlackListed) {
        _strcat_a(szConsoleText, " - found in blacklist, skip\r\n");
        wColor = FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    }
    else {
        _strcat_a(szConsoleText, "\r\n");
    }

    FuzzShowMessage(szConsoleText, wColor);
}

/*
* FuzzRunThreadWithWait
*
* Purpose:
*
* Run fuzzing thread and wait.
*
*/
VOID FuzzRunThreadWithWait(
    _In_ CALL_PARAM *CallParams
)
{
    HANDLE hThread;
    DWORD dwThreadId;
    CHAR szConsoleText[100];

    hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)FuzzThreadProc,
        (LPVOID)CallParams, 0, &dwThreadId);

    if (hThread) {
        if (WaitForSingleObject(hThread, CallParams->ThreadTimeout) == WAIT_TIMEOUT) {
            TerminateThread(hThread, MAXDWORD);
            _strcpy_a(szConsoleText, "\t^Timeout reached for callproc of service: ");
            ultostr_a(CallParams->Syscall, _strend_a(szConsoleText));
            _strcat_a(szConsoleText, "\r\n");
            FuzzShowMessage(szConsoleText, 0);
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
    _In_ NTCALL_CONTEXT *Context
)
{
    BOOL probeWin32k = Context->ProbeWin32k, bSkip = FALSE;
    BLACKLIST *BlackList = &Context->BlackList;
    ULONG_PTR hNtdll = Context->hNtdll;
    PRAW_SERVICE_TABLE ServiceTable = &Context->ServiceTable;
    ULONG c, sid;

    CALL_PARAM CallParams;

    PCHAR  ServiceName, pLog;

    CHAR szOut[MAX_PATH * 2];

    FuzzShowMessage("[+] Entering FuzzRun()\r\n",
        FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);

    //
    // If single syscall mode, just call it.
    //
    if (Context->ProbeSingleSyscall) {

        //
        // Query service name.
        //
        if (probeWin32k) {
            sid = Context->SingleSyscallId - W32SYSCALLSTART;
            ServiceName = Context->Win32pServiceTableNames[sid];
        }
        else {
            sid = Context->SingleSyscallId;
            ServiceName = (PCHAR)PELoaderGetProcNameBySDTIndex(hNtdll, sid);
        }

        //
        // Log service name.
        //
        /*
        if (Context->LogEnabled)
            FuzzLogCallName(Context->LogHandle, ServiceName);
        */

        //
        // Output service information to console.
        //
        _strcpy_a(szOut, "\tProbing #");
        ultostr_a(Context->SingleSyscallId, _strend_a(szOut));
        pLog = _strcat_a(szOut, "\t");
        if (ServiceName) {
            _strncpy_a(pLog, MAX_PATH, ServiceName, MAX_PATH);
        }
        else {
            _strcpy_a(pLog, "Unknown");
        }
        _strcat_a(pLog, "\r\n");
        FuzzShowMessage(szOut, 0);

        //
        // Setup service call parameters and call it in separate thread.
        //
        CallParams.ParametersInStack = Context->ServiceTable.StackArgumentTable[sid];
        CallParams.Syscall = Context->SingleSyscallId;
        CallParams.ThreadTimeout = INFINITE;
        CallParams.NumberOfPassesForCall = Context->SyscallPassCount;

        FuzzRunThreadWithWait(&CallParams);
    }
    else {

        for (c = 0; c < ServiceTable->CountOfEntries; c++) {

            //
            // Query service name.
            //
            if (probeWin32k) {
                ServiceName = Context->Win32pServiceTableNames[c];
                sid = W32SYSCALLSTART + c;
            }
            else {
                ServiceName = (PCHAR)PELoaderGetProcNameBySDTIndex(hNtdll, c);
                sid = c;
            }

            if (ServiceName) {
                bSkip = BlackListEntryPresent(BlackList, (LPCSTR)ServiceName);
            }

            //
            // Output service information to console.
            //
            PrintServiceInformation(ServiceTable->StackArgumentTable[c] / 4,
                sid,
                ServiceName,
                bSkip);

            if (bSkip) {
                bSkip = FALSE;
                continue;
            }

            //
            // Log service name.
            //
            /*
            if (Context->LogEnabled)
                FuzzLogCallName(Context->LogHandle, ServiceName);
            */

            //
            // Setup service call parameters and call it in separate thread.
            //
            CallParams.Syscall = sid;
            CallParams.ParametersInStack = Context->ServiceTable.StackArgumentTable[c];
            CallParams.ThreadTimeout = FUZZ_THREAD_TIMEOUT;
            CallParams.NumberOfPassesForCall = Context->SyscallPassCount;

            if (Context->LogEnabled)
                CallParams.ThreadTimeout *= 4; //extend timeout with logging

            FuzzRunThreadWithWait(&CallParams);

        }

    }

    FuzzShowMessage("[-] Leaving FuzzRun()\r\n",
        FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
}
