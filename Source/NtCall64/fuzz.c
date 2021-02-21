/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2021
*
*  TITLE:       FUZZ.C
*
*  VERSION:     1.35
*
*  DATE:        21 Feb 2021
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
#include "tables.h"

#ifdef __cplusplus 
extern "C" {
#endif
    NTSTATUS ntSyscallGate(ULONG ServiceId, ULONG ArgumentCount, ULONG_PTR *Arguments);
#ifdef __cplusplus
}
#endif

/*
* FuzzEnumWin32uServices
*
* Purpose:
*
* Enumerate win32u module services to the table.
*
*/
_Success_(return != 0)
ULONG FuzzEnumWin32uServices(
    _In_ HANDLE HeapHandle,
    _In_ LPVOID Module,
    _Out_ PWIN32_SHADOWTABLE * Table
)
{
    PIMAGE_NT_HEADERS           NtHeaders;
    PIMAGE_EXPORT_DIRECTORY		exp;
    PDWORD						FnPtrTable, NameTable;
    PWORD						NameOrdTable;
    ULONG_PTR					fnptr, exprva, expsize;
    ULONG						c, n, result;
    PWIN32_SHADOWTABLE			NewEntry;

    NtHeaders = RtlImageNtHeader(Module);
    if (NtHeaders->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT)
        return 0;

    exprva = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exprva == 0)
        return 0;

    expsize = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    exp = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)Module + exprva);
    FnPtrTable = (PDWORD)((ULONG_PTR)Module + exp->AddressOfFunctions);
    NameTable = (PDWORD)((ULONG_PTR)Module + exp->AddressOfNames);
    NameOrdTable = (PWORD)((ULONG_PTR)Module + exp->AddressOfNameOrdinals);

    result = 0;

    for (c = 0; c < exp->NumberOfFunctions; ++c)
    {
        fnptr = (ULONG_PTR)Module + FnPtrTable[c];
        if (*(PDWORD)fnptr != 0xb8d18b4c) //mov r10, rcx; mov eax
            continue;

        NewEntry = (PWIN32_SHADOWTABLE)HeapAlloc(HeapHandle,
            HEAP_ZERO_MEMORY, sizeof(WIN32_SHADOWTABLE));

        if (NewEntry == NULL)
            break;

        NewEntry->Index = *(PDWORD)(fnptr + 4);

        for (n = 0; n < exp->NumberOfNames; ++n)
        {
            if (NameOrdTable[n] == c)
            {
                _strncpy_a(&NewEntry->Name[0],
                    sizeof(NewEntry->Name),
                    (LPCSTR)((ULONG_PTR)Module + NameTable[n]),
                    sizeof(NewEntry->Name));

                break;
            }
        }

        ++result;

        *Table = NewEntry;
        Table = &NewEntry->NextService;
    }

    return result;
}

/*
* FuzzResolveW32kServiceNameById
*
* Purpose:
*
* Return service name if found by id in prebuilt lookup table.
*
*/
PCHAR FuzzResolveW32kServiceNameById(
    _In_ ULONG ServiceId,
    _In_opt_ PWIN32_SHADOWTABLE ShadowTable
)
{
    PWIN32_SHADOWTABLE Entry = ShadowTable;

    while (Entry) {

        if (Entry->Index == ServiceId) {
            return Entry->Name;
        }
        Entry = Entry->NextService;
    }

    return NULL;
}

/*
* FuzzFindKiServiceTable
*
* Purpose:
*
* Locate KiServiceTable in mapped ntoskrnl copy.
*
*/
BOOL FuzzFindKiServiceTable(
    _In_ ULONG_PTR MappedImageBase,
    _In_ PRAW_SERVICE_TABLE ServiceTable
)
{
    ULONG_PTR             SectionPtr = 0;
    IMAGE_NT_HEADERS* NtHeaders = RtlImageNtHeader((PVOID)MappedImageBase);
    IMAGE_SECTION_HEADER* SectionTableEntry;
    ULONG                 c, p, SectionSize = 0, SectionVA = 0;

    const BYTE  KiSystemServiceStartPattern[] = { 0x45, 0x33, 0xC9, 0x44, 0x8B, 0x05 };

    SectionTableEntry = (PIMAGE_SECTION_HEADER)((PCHAR)NtHeaders +
        sizeof(ULONG) +
        sizeof(IMAGE_FILE_HEADER) +
        NtHeaders->FileHeader.SizeOfOptionalHeader);

    c = NtHeaders->FileHeader.NumberOfSections;
    while (c > 0) {
        if (*(PULONG)SectionTableEntry->Name == 'EGAP')
            if ((SectionTableEntry->Name[4] == 'L') &&
                (SectionTableEntry->Name[5] == 'K') &&
                (SectionTableEntry->Name[6] == 0))

            {
                SectionVA = SectionTableEntry->VirtualAddress;
                SectionPtr = (ULONG_PTR)(MappedImageBase + SectionVA);
                SectionSize = SectionTableEntry->Misc.VirtualSize;
                break;
            }
        c -= 1;
        SectionTableEntry += 1;
    }

    if ((SectionPtr == 0) || (SectionSize == 0) || (SectionVA == 0)) {
        return FALSE;
    }

    p = 0;
    for (c = 0; c < (SectionSize - sizeof(KiSystemServiceStartPattern)); c++)
        if (RtlCompareMemory(
            (PVOID)(SectionPtr + c),
            KiSystemServiceStartPattern,
            sizeof(KiSystemServiceStartPattern)) == sizeof(KiSystemServiceStartPattern))
        {
            p = SectionVA + c;
            break;
        }

    if (p == 0)
        return FALSE;

    p += 3;
    c = *((PULONG)(MappedImageBase + p + 3)) + 7 + p;
    ServiceTable->CountOfEntries = *((PULONG)(MappedImageBase + c));
    p += 7;
    c = *((PULONG)(MappedImageBase + p + 3)) + 7 + p;
    ServiceTable->StackArgumentTable = (PBYTE)MappedImageBase + c;
    p += 7;
    c = *((PULONG)(MappedImageBase + p + 3)) + 7 + p;
    ServiceTable->ServiceTable = (LPVOID*)(MappedImageBase + c);

    return TRUE;
}

/*
* FuzzFindW32pServiceTable
*
* Purpose:
*
* Locate shadow table info in mapped win32k copy.
*
*/
BOOL FuzzFindW32pServiceTable(
    _In_ HMODULE MappedImageBase,
    _In_ PRAW_SERVICE_TABLE ServiceTable
)
{
    PULONG ServiceLimit;

    ServiceLimit = (ULONG*)GetProcAddress(MappedImageBase, "W32pServiceLimit");
    if (ServiceLimit == NULL)
        return FALSE;

    ServiceTable->CountOfEntries = *ServiceLimit;
    ServiceTable->StackArgumentTable = (PBYTE)GetProcAddress(MappedImageBase, "W32pArgumentTable");
    if (ServiceTable->StackArgumentTable == NULL)
        return FALSE;

    ServiceTable->ServiceTable = (LPVOID*)GetProcAddress(MappedImageBase, "W32pServiceTable");
    if (ServiceTable->ServiceTable == NULL)
        return FALSE;

    return TRUE;
}

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
    _In_ ULONG ParametersInStack,
    _In_ PVOID LogParams
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

        FuzzLogCallParameters((PNTCALL_LOG_PARAMS)LogParams,
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
    CHAR                  **lpServiceNames;

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
        ConsoleShowMessage("[!] Failed to query win32k.sys version information.\r\n",
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
        if (ServiceTable->CountOfEntries == 0 || ServiceTable->CountOfEntries > 0x10000)
            return FALSE;
        break;
    }

    lpServiceNames = (CHAR**)HeapAlloc(GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        ServiceTable->CountOfEntries * sizeof(PCHAR));

    if (lpServiceNames == NULL)
        return FALSE;

    Context->Win32pServiceTableNames = lpServiceNames;

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
            lpServiceNames[i] = Names[i];
        }
    }
    else {

        //
        // 
        //
        if (BuildNumber >= 14393) {

            win32u = LoadLibraryEx(TEXT("win32u.dll"), NULL, 0);
            if (win32u == NULL) {
                ConsoleShowMessage("[!] Failed to load win32u.dll.\r\n",
                    FOREGROUND_RED | FOREGROUND_INTENSITY);
                return FALSE;
            }

            win32uLimit = FuzzEnumWin32uServices(GetProcessHeap(), (LPVOID)win32u, &ShadowTable);

            if ((win32uLimit != ServiceTable->CountOfEntries) || (ShadowTable == NULL)) {
                ConsoleShowMessage("[!] Win32u services enumeration failed.\r\n",
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

                    ConsoleShowMessage("[!]FuzzLookupWin32kNames HDE error.\r\n",
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
            lpServiceNames[i] = ServiceName;
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
        DoSystemCall(Context->Syscall, Context->ParametersInStack, Context->LogParams);
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

    ConsoleShowMessage(szConsoleText, wColor);
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
#pragma warning(push)
#pragma warning(disable: 6258)
            TerminateThread(hThread, MAXDWORD);
#pragma warning(pop)
            _strcpy_a(szConsoleText, "\t^Timeout reached for callproc of service: ");
            ultostr_a(CallParams->Syscall, _strend_a(szConsoleText));
            _strcat_a(szConsoleText, "\r\n");
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

    ConsoleShowMessage("[+] Entering FuzzRun()\r\n",
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
        ConsoleShowMessage(szOut, 0);

        //
        // Setup service call parameters and call it in separate thread.
        //
        CallParams.ParametersInStack = Context->ServiceTable.StackArgumentTable[sid];
        CallParams.Syscall = Context->SingleSyscallId;
        CallParams.ThreadTimeout = INFINITE;
        CallParams.NumberOfPassesForCall = Context->SyscallPassCount;
        CallParams.LogParams = &g_Log;

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
            CallParams.ThreadTimeout = (Context->ThreadWaitTimeout * 1000);
            CallParams.NumberOfPassesForCall = Context->SyscallPassCount;
            CallParams.LogParams = &g_Log;

            if (Context->LogEnabled)
                CallParams.ThreadTimeout *= 4; //extend timeout with logging

            FuzzRunThreadWithWait(&CallParams);

        }

    }

    ConsoleShowMessage("[-] Leaving FuzzRun()\r\n",
        FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
}
