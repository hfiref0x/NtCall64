/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2023
*
*  TITLE:       FUZZ.C
*
*  VERSION:     1.37
*
*  DATE:        04 Aug 2023
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
    NTSTATUS ntSyscallGate(ULONG ServiceId, ULONG ArgumentCount, ULONG_PTR* Arguments);
#ifdef __cplusplus
}
#endif

#define FUZZDATA_COUNT 13
const ULONG_PTR FuzzData[FUZZDATA_COUNT] = {
    0x0000000000000000, 0x000000000000ffff, 0x000000000000fffe, 0x00007ffffffeffff,
    0x00007ffffffefffe, 0x00007fffffffffff, 0x00007ffffffffffe, 0x0000800000000000,
    0x8000000000000000, 0xffff080000000000, 0xfffff80000000000, 0xffff800000000000,
    0xffff800000000001
};


/*
* FuzzEnumWin32uServices
*
* Purpose:
*
* Enumerate win32u module services to the table.
*
*/
ULONG FuzzEnumWin32uServices(
    _In_ HANDLE HeapHandle,
    _In_ LPVOID ModuleBase,
    _Inout_ PWIN32_SHADOWTABLE* Table
)
{
    ULONG i, j, result = 0, exportSize;
    PBYTE fnptr;
    PDWORD funcTable, nameTableBase;
    PWORD nameOrdinalTableBase;
    PWIN32_SHADOWTABLE w32kTableEntry;
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory;

    pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RtlImageDirectoryEntryToData(ModuleBase,
        TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &exportSize);

    if (pImageExportDirectory) {

        nameTableBase = (PDWORD)RtlOffsetToPointer(ModuleBase, pImageExportDirectory->AddressOfNames);
        nameOrdinalTableBase = (PUSHORT)RtlOffsetToPointer(ModuleBase, pImageExportDirectory->AddressOfNameOrdinals);
        funcTable = (PDWORD)RtlOffsetToPointer(ModuleBase, pImageExportDirectory->AddressOfFunctions);

        result = 0;

        for (i = 0; i < pImageExportDirectory->NumberOfFunctions; ++i) {

            fnptr = (PBYTE)RtlOffsetToPointer(ModuleBase, funcTable[nameOrdinalTableBase[i]]);
            if (*(PDWORD)fnptr != 0xb8d18b4c) //mov r10, rcx; mov eax
                continue;

            w32kTableEntry = (PWIN32_SHADOWTABLE)HeapAlloc(HeapHandle,
                HEAP_ZERO_MEMORY, sizeof(WIN32_SHADOWTABLE));

            if (w32kTableEntry == NULL)
                break;

            w32kTableEntry->Index = *(PDWORD)(fnptr + 4);

            for (j = 0; j < pImageExportDirectory->NumberOfNames; ++j)
            {
                if (nameOrdinalTableBase[j] == i)
                {
                    _strncpy_a(&w32kTableEntry->Name[0],
                        sizeof(w32kTableEntry->Name),
                        (LPCSTR)RtlOffsetToPointer(ModuleBase, nameTableBase[j]),
                        sizeof(w32kTableEntry->Name));

                    break;
                }
            }

            ++result;

            *Table = w32kTableEntry;
            Table = &w32kTableEntry->NextService;
        }
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
BOOLEAN FuzzFindKiServiceTable(
    _In_ PVOID MappedImageBase,
    _In_ PRAW_SERVICE_TABLE ServiceTable
)
{
    ULONG_PTR SectionPtr = 0;
    PBYTE ptrCode = (PBYTE)MappedImageBase;
    IMAGE_NT_HEADERS* NtHeaders = RtlImageNtHeader(MappedImageBase);
    IMAGE_SECTION_HEADER* SectionTableEntry;
    ULONG c, p, SectionSize = 0, SectionVA = 0;

    const BYTE KiSystemServiceStartPattern[] = { 0x45, 0x33, 0xC9, 0x44, 0x8B, 0x05 };

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
                SectionPtr = (ULONG_PTR)RtlOffsetToPointer(MappedImageBase, SectionVA);
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
    c = *((PULONG)(ptrCode + p + 3)) + 7 + p;
    ServiceTable->CountOfEntries = *((PULONG)(ptrCode + c));
    p += 7;
    c = *((PULONG)(ptrCode + p + 3)) + 7 + p;
    ServiceTable->StackArgumentTable = (PBYTE)ptrCode + c;
    p += 7;
    c = *((PULONG)(ptrCode + p + 3)) + 7 + p;
    ServiceTable->ServiceTable = (LPVOID*)(ptrCode + c);

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
BOOLEAN FuzzFindW32pServiceTable(
    _In_ PVOID MappedImageBase,
    _In_ PRAW_SERVICE_TABLE ServiceTable
)
{
    PULONG ServiceLimit;

    ServiceLimit = (ULONG*)supLdrGetProcAddressEx(MappedImageBase, "W32pServiceLimit");
    if (ServiceLimit == NULL)
        return FALSE;

    ServiceTable->CountOfEntries = *ServiceLimit;
    ServiceTable->StackArgumentTable = (PBYTE)supLdrGetProcAddressEx(MappedImageBase, "W32pArgumentTable");
    if (ServiceTable->StackArgumentTable == NULL)
        return FALSE;

    ServiceTable->ServiceTable = (LPVOID*)supLdrGetProcAddressEx(MappedImageBase, "W32pServiceTable");
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
VOID DoSystemCall(
    _In_ ULONG ServiceId,
    _In_ ULONG ParametersInStack,
    _In_ PVOID LogParams
)
{
    ULONG c;
    ULONG_PTR args[MAX_PARAMETERS];

    RtlSecureZeroMemory(args, sizeof(args));

    ParametersInStack /= 4;

    for (c = 0; c < ParametersInStack + 4; c++) {
        args[c] = FuzzData[__rdtsc() % FUZZDATA_COUNT];
    }

    if (g_ctx.LogEnabled) {

        FuzzLogCallParameters((PNTCALL_LOG_PARAMS)LogParams,
            ServiceId,
            ParametersInStack + 4,
            (ULONG_PTR*)&args);

    }

    ntSyscallGate(ServiceId, ParametersInStack + 4, args);
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
    ULONG dwBuildNumber = 0, i;
    PVOID MappedImageBase = Context->SystemModuleBase;
    PIMAGE_NT_HEADERS NtHeaders = RtlImageNtHeader((PVOID)MappedImageBase);
    PRAW_SERVICE_TABLE ServiceTable = &Context->ServiceTable;
    ULONG_PTR Address;
    PCHAR* lpServiceNames;

    DWORD64* pW32pServiceTable = NULL;
    PCHAR* pszNames = NULL;
    PCHAR pfn;

    IMAGE_IMPORT_BY_NAME* ImportEntry;

    HMODULE win32u = NULL;
    ULONG win32uLimit;
    PWIN32_SHADOWTABLE ShadowTable = NULL;

    PCHAR lpServiceName;

    hde64s hs;

#ifdef _DEBUG
    dwBuildNumber = g_ctx.OsVersion.dwBuildNumber;
#else
    dwBuildNumber = g_ctx.OsVersion.dwBuildNumber;
#endif

    switch (dwBuildNumber) {

    case NT_WIN7_RTM:
    case NT_WIN7_SP1:
        if (ServiceTable->CountOfEntries != W32pServiceTableLimit_7601)
            return FALSE;
        pszNames = (CHAR**)W32pServiceTableNames_7601;
        break;

    case NT_WIN8_RTM:
        if (ServiceTable->CountOfEntries != W32pServiceTableLimit_9200)
            return FALSE;
        pszNames = (CHAR**)W32pServiceTableNames_9200;
        break;

    case NT_WIN8_BLUE:
        if (ServiceTable->CountOfEntries != W32pServiceTableLimit_9600)
            return FALSE;
        pszNames = (CHAR**)W32pServiceTableNames_9600;
        break;

    default:
        if (ServiceTable->CountOfEntries == 0 || ServiceTable->CountOfEntries > 0x10000)
            return FALSE;
        break;
    }

    lpServiceNames = (CHAR**)supHeapAlloc(ServiceTable->CountOfEntries * sizeof(PCHAR));

    if (lpServiceNames == NULL)
        return FALSE;

    Context->Win32pServiceTableNames = lpServiceNames;

    pW32pServiceTable = (DWORD64*)ServiceTable->ServiceTable;

    //
    // Query service names.
    // If win32k version below 10240 copy them from predefined array.
    // Otherwise lookup them dynamically.
    //
    if (dwBuildNumber < NT_WIN10_THRESHOLD1) {
        if (pszNames == NULL)
            return FALSE;

        for (i = 0; i < ServiceTable->CountOfEntries; i++) {
            lpServiceNames[i] = pszNames[i];
        }
    }
    else {

        if (dwBuildNumber >= NT_WIN10_REDSTONE1) {

            win32u = GetModuleHandle(TEXT("win32u.dll"));
            if (win32u == NULL) {
                ConsoleShowMessage("[!] Failed to reference win32u.dll.\r\n",
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

            lpServiceName = "UnknownName";

            if (dwBuildNumber <= NT_WIN10_THRESHOLD2) {
                pfn = (PCHAR)(pW32pServiceTable[i] - NtHeaders->OptionalHeader.ImageBase + (ULONG_PTR)MappedImageBase);
                hde64_disasm((void*)pfn, &hs);
                if (hs.flags & F_ERROR) {

                    ConsoleShowMessage("[!]FuzzLookupWin32kNames HDE error.\r\n",
                        FOREGROUND_RED | FOREGROUND_INTENSITY);

                    break;
                }
                Address = (ULONG_PTR)MappedImageBase + *(ULONG_PTR*)(pfn + hs.len + *(DWORD*)(pfn + (hs.len - 4)));
                if (Address) {
                    ImportEntry = (IMAGE_IMPORT_BY_NAME*)Address;
                    lpServiceName = ImportEntry->Name;
                }
            }
            else if (dwBuildNumber >= NT_WIN10_REDSTONE1) {

                lpServiceName = FuzzResolveW32kServiceNameById(i + W32SYSCALLSTART, ShadowTable);
                if (lpServiceName == NULL)
                    lpServiceName = "UnknownName";

            }
            lpServiceNames[i] = lpServiceName;
        }
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
    CHAR* pLog;
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
    _In_ CALL_PARAM* CallParams
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
    _In_ NTCALL_CONTEXT* Context
)
{
    BOOL probeWin32k = Context->ProbeWin32k, bSkip = FALSE;
    BLACKLIST* BlackList = &Context->BlackList;
    PVOID ntdllBase = Context->NtdllBase;
    PRAW_SERVICE_TABLE ServiceTable = &Context->ServiceTable;
    ULONG c, sid;

    CALL_PARAM CallParams;

    PCHAR lpServiceName, pLog;

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
            sid = Context->u1.SingleSyscallId - W32SYSCALLSTART;
            lpServiceName = Context->Win32pServiceTableNames[sid];
        }
        else {
            sid = Context->u1.SingleSyscallId;
            lpServiceName = supLdrGetProcNameBySDTIndex(ntdllBase, sid);
        }

        //
        // Output service information to console.
        //
        _strcpy_a(szOut, "\tProbing #");
        ultostr_a(Context->u1.SingleSyscallId, _strend_a(szOut));
        pLog = _strcat_a(szOut, "\t");
        if (lpServiceName) {
            _strncpy_a(pLog, MAX_PATH, lpServiceName, MAX_PATH);
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
        CallParams.Syscall = Context->u1.SingleSyscallId;
        CallParams.ThreadTimeout = INFINITE;
        CallParams.NumberOfPassesForCall = Context->SyscallPassCount;
        CallParams.LogParams = &g_Log;

        FuzzRunThreadWithWait(&CallParams);
    }
    else {

        c = 0;
        if (Context->ProbeFromSyscallId) {
            if (Context->ProbeWin32k)
                c = Context->u1.StartingSyscallId - W32SYSCALLSTART;
            else
                c = Context->u1.StartingSyscallId;
        }

        for (; c < ServiceTable->CountOfEntries; c++) {

            //
            // Query service name.
            //
            if (probeWin32k) {
                lpServiceName = Context->Win32pServiceTableNames[c];
                sid = W32SYSCALLSTART + c;
            }
            else {
                lpServiceName = supLdrGetProcNameBySDTIndex(ntdllBase, c);
                sid = c;
            }

            if (lpServiceName) {
                bSkip = BlackListEntryPresent(BlackList, (LPCSTR)lpServiceName);
            }

            //
            // Output service information to console.
            //
            PrintServiceInformation(ServiceTable->StackArgumentTable[c] / 4,
                sid,
                lpServiceName,
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
