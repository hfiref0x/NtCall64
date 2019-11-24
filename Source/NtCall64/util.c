/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2019
*
*  TITLE:       UTIL.C
*
*  VERSION:     1.33
*
*  DATE:        22 Nov 2019
*
*  Program support routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "main.h"

#pragma comment(lib, "Version.lib")

VOID FORCEINLINE InitializeListHead(
    _In_ PLIST_ENTRY ListHead
)
{
    ListHead->Flink = ListHead->Blink = ListHead;
}

VOID FORCEINLINE InsertTailList(
    _Inout_ PLIST_ENTRY ListHead,
    _Inout_ PLIST_ENTRY Entry
)
{
    PLIST_ENTRY Blink;

    Blink = ListHead->Blink;
    Entry->Flink = ListHead;
    Entry->Blink = Blink;
    Blink->Flink = Entry;
    ListHead->Blink = Entry;
}

/*
* GetImageVersionInfo
*
* Purpose:
*
* Return version numbers from version info.
*
*/
BOOL GetImageVersionInfo(
    _In_ LPWSTR lpFileName,
    _Out_opt_ ULONG *MajorVersion,
    _Out_opt_ ULONG *MinorVersion,
    _Out_opt_ ULONG *Build,
    _Out_opt_ ULONG *Revision
)
{
    BOOL bResult = FALSE;
    DWORD dwHandle, dwSize;
    PVOID vinfo = NULL;
    UINT Length;
    VS_FIXEDFILEINFO *pFileInfo;

    //
    // Assume failure.
    //
    if (MajorVersion)
        *MajorVersion = 0;
    if (MinorVersion)
        *MinorVersion = 0;
    if (Build)
        *Build = 0;
    if (Revision)
        *Revision = 0;

    dwHandle = 0;
    dwSize = GetFileVersionInfoSize(lpFileName, &dwHandle);
    if (dwSize) {
        vinfo = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
        if (vinfo) {
            if (GetFileVersionInfo(lpFileName, 0, dwSize, vinfo)) {
                bResult = VerQueryValue(vinfo, TEXT("\\"), (LPVOID *)&pFileInfo, (PUINT)&Length);
                if (bResult) {
                    if (MajorVersion)
                        *MajorVersion = HIWORD(pFileInfo->dwFileVersionMS);
                    if (MinorVersion)
                        *MinorVersion = LOWORD(pFileInfo->dwFileVersionMS);
                    if (Build)
                        *Build = HIWORD(pFileInfo->dwFileVersionLS);
                    if (Revision)
                        *Revision = LOWORD(pFileInfo->dwFileVersionLS);
                }
            }
            HeapFree(GetProcessHeap(), 0, vinfo);
        }
    }
    return bResult;
}

/*
* FuzzShowMessage
*
* Purpose:
*
* Output text to screen.
*
*/
VOID FuzzShowMessage(
    _In_ LPCSTR lpMessage,
    _In_opt_ WORD wColor
)
{
    CONSOLE_SCREEN_BUFFER_INFO csbi;

    ULONG r, sz;

    WORD SavedAttributes = 0;

    HANDLE hStdHandle = GetStdHandle(STD_OUTPUT_HANDLE);


    sz = (DWORD)_strlen_a(lpMessage);
    if (sz == 0)
        return;

    if (wColor) {

        RtlSecureZeroMemory(&csbi, sizeof(csbi));

        GetConsoleScreenBufferInfo(hStdHandle, &csbi);

        SavedAttributes = csbi.wAttributes;

        SetConsoleTextAttribute(hStdHandle, wColor);

    }

    WriteFile(hStdHandle, lpMessage, sz, &r, NULL);

    if (wColor) {
        SetConsoleTextAttribute(hStdHandle, SavedAttributes);
    }
}


/*
* BlackListCreateFromFile
*
* Purpose:
*
* Read blacklist from ini file to allocated memory.
*
*/
BOOL BlackListCreateFromFile(
    _In_ BLACKLIST *BlackList,
    _In_ LPCSTR ConfigFileName,
    _In_ LPCSTR ConfigSectionName
)
{
    BOOL    bResult = FALSE;
    LPSTR   Section = NULL, SectionPtr;
    ULONG   nSize, SectionSize, BytesRead, Length;
    CHAR    ConfigFilePath[MAX_PATH + 16];

    HANDLE BlackListHeap;

    PBL_ENTRY Entry = NULL;

    do {

        RtlSecureZeroMemory(ConfigFilePath, sizeof(ConfigFilePath));
        GetModuleFileNameA(NULL, (LPSTR)&ConfigFilePath, MAX_PATH);
        _filepath_a(ConfigFilePath, ConfigFilePath);
        _strcat_a(ConfigFilePath, ConfigFileName);

        BlackListHeap = HeapCreate(HEAP_GROWABLE, 0, 0);
        if (BlackListHeap == NULL)
            break;

        HeapSetInformation(BlackListHeap, HeapEnableTerminationOnCorruption, NULL, 0);

        nSize = 2 * (1024 * 1024);

        Section = (LPSTR)HeapAlloc(BlackListHeap, HEAP_ZERO_MEMORY, nSize);
        if (Section == NULL)
            break;

        SectionSize = GetPrivateProfileSectionA(ConfigSectionName, Section, nSize, ConfigFilePath);
        if (SectionSize == 0)
            break;

        BytesRead = 0;
        SectionPtr = Section;

        RtlSecureZeroMemory(BlackList, sizeof(BLACKLIST));

        InitializeListHead(&BlackList->ListHead);

        do {

            if (*SectionPtr == 0)
                break;

            Length = (ULONG)_strlen_a(SectionPtr) + 1;
            BytesRead += Length;

            Entry = (BL_ENTRY*)HeapAlloc(BlackListHeap, HEAP_ZERO_MEMORY, sizeof(BL_ENTRY));
            if (Entry == NULL) {
                goto Cleanup;
            }

            Entry->Hash = BlackListHashString(SectionPtr);

            InsertTailList(&BlackList->ListHead, &Entry->ListEntry);

            BlackList->NumberOfEntries += 1;

            SectionPtr += Length;

        } while (BytesRead < SectionSize);

        BlackList->HeapHandle = BlackListHeap;

        bResult = TRUE;

    } while (FALSE);

Cleanup:

    if (bResult == FALSE) {
        if (BlackListHeap) HeapDestroy(BlackListHeap);
    }
    return bResult;
}

/*
* BlackListEntryPresent
*
* Purpose:
*
* Return TRUE if syscall is in blacklist.
*
*/
BOOL BlackListEntryPresent(
    _In_ BLACKLIST *BlackList,
    _In_ LPCSTR SyscallName
)
{
    DWORD Hash = BlackListHashString(SyscallName);

    PLIST_ENTRY Head, Next;
    BL_ENTRY *entry;

    Head = &BlackList->ListHead;
    Next = Head->Flink;
    while ((Next != NULL) && (Next != Head)) {
        entry = CONTAINING_RECORD(Next, BL_ENTRY, ListEntry);
        if (entry->Hash == Hash)
            return TRUE;

        Next = Next->Flink;
    }

    return FALSE;
}

/*
* BlackListHashString
*
* Purpose:
*
* Hash string.
*
*/
DWORD BlackListHashString(
    _In_ LPCSTR Name
)
{
    DWORD Hash = 5381;
    PCHAR p = (PCHAR)Name;

    while (*p)
        Hash = 33 * Hash ^ *p++;

    return Hash;
}

/*
* BlackListDestroy
*
* Purpose:
*
* Destroy blacklist heap and zero blacklist structure.
*
*/
VOID BlackListDestroy(
    _In_ BLACKLIST *BlackList
)
{
    if (BlackList) {
        if (BlackList->HeapHandle) HeapDestroy(BlackList->HeapHandle);
        RtlSecureZeroMemory(BlackList, sizeof(BLACKLIST));
    }
}

/*
* GetCommandLineOption
*
* Purpose:
*
* Parse command line options.
*
*/
BOOL GetCommandLineOption(
    _In_ LPCTSTR OptionName,
    _In_ BOOL IsParametric,
    _Out_writes_opt_z_(ValueSize) LPTSTR OptionValue,
    _In_ ULONG ValueSize
)
{
    LPTSTR	cmdline = GetCommandLine();
    TCHAR   Param[64];
    ULONG   rlen;
    int		i = 0;

    while (GetCommandLineParam(cmdline, i, Param, sizeof(Param), &rlen))
    {
        if (rlen == 0)
            break;

        if (_strcmp(Param, OptionName) == 0)
        {
            if (IsParametric)
                return GetCommandLineParam(cmdline, i + 1, OptionValue, ValueSize, &rlen);

            return TRUE;
        }
        ++i;
    }

    return 0;
}

/*
* FuzzOpenLog
*
* Purpose:
*
* Open COM1 port for logging.
*
*/
BOOL FuzzOpenLog(
    _Out_ PHANDLE LogHandle,
    _Out_opt_ PDWORD LastError
)
{
    HANDLE	hFile;
    CHAR	szWelcome[128];
    DWORD	bytesIO;

    hFile = CreateFile(TEXT("COM1"),
        GENERIC_WRITE | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_WRITE_THROUGH,
        NULL);

    if (LastError)
        *LastError = GetLastError();

    if (hFile != INVALID_HANDLE_VALUE) {

        _strcpy_a(szWelcome, "\r\n[NC64] Logging start.\r\n");
        WriteFile(hFile, (LPCVOID)&szWelcome,
            (DWORD)_strlen_a(szWelcome), &bytesIO, NULL);

        *LogHandle = hFile;
        return TRUE;
    }

    *LogHandle = INVALID_HANDLE_VALUE;

    return FALSE;
}

/*
* FuzzCloseLog
*
* Purpose:
*
* Close COM1 port.
*
*/
VOID FuzzCloseLog(
    _Inout_ PHANDLE LogHandle
)
{
    CHAR	szBye[128];
    DWORD	bytesIO;

    HANDLE logHandle = *LogHandle;

    if (logHandle == INVALID_HANDLE_VALUE)
        return;

    _strcpy_a(szBye, "\r\n[NC64] Log stop.\r\n");
    WriteFile(logHandle,
        (LPCVOID)&szBye, (DWORD)_strlen_a(szBye), &bytesIO, NULL);

    CloseHandle(logHandle);
    *LogHandle = INVALID_HANDLE_VALUE;
}

/*
* FuzzLogCallName
*
* Purpose:
*
* Send syscall name to the log before it is not too late.
*
*/
VOID FuzzLogCallName(
    _In_ HANDLE LogHandle,
    _In_ LPCSTR ServiceName
)
{
    ULONG bytesIO;
    CHAR szLog[128];

    if (LogHandle) {
        WriteFile(LogHandle, (LPCVOID)ServiceName,
            (DWORD)_strlen_a(ServiceName), &bytesIO, NULL);

        _strcpy_a(szLog, "\r\n");
        WriteFile(LogHandle, (LPCVOID)&szLog,
            (DWORD)_strlen_a(szLog), &bytesIO, NULL);
    }
}

/*
* FuzzLogCallParameters
*
* Purpose:
*
* Send syscall parameters to the log before it is not too late.
*
*/
VOID FuzzLogCallParameters(
    _In_ HANDLE LogHandle,
    _In_ ULONG ServiceId,
    _In_ ULONG NumberOfArguments,
    _In_ ULONG_PTR *Arguments
)
{
    ULONG i;
    DWORD bytesIO;
    CHAR szLog[2048];

    if (LogHandle == INVALID_HANDLE_VALUE)
        return;

    _strcpy_a(szLog, "[NC64] ");
    ultostr_a(ServiceId, _strend_a(szLog));
    ultostr_a(NumberOfArguments, _strcat_a(szLog, "\t"));
    _strcat_a(szLog, "\t");

    for (i = 0; i < NumberOfArguments; i++) {
        u64tohex_a(Arguments[i], _strcat_a(szLog, " "));
    }
    _strcat_a(szLog, "\r\n");
    WriteFile(LogHandle, (LPCVOID)&szLog,
        (DWORD)_strlen_a(szLog), &bytesIO, NULL);
}

/*
* IsUserInAdminGroup
*
* Purpose:
*
* Returns TRUE if current user is in admin group.
*
*/
BOOLEAN IsUserInAdminGroup()
{
    BOOLEAN bResult = FALSE;
    HANDLE hToken;

    ULONG returnLength, i;

    PSID pSid = NULL;

    PTOKEN_GROUPS ptg = NULL;

    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {

        GetTokenInformation(hToken, TokenGroups, NULL, 0, &returnLength);

        ptg = (PTOKEN_GROUPS)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)returnLength);
        if (ptg) {

            if (GetTokenInformation(hToken,
                TokenGroups,
                ptg,
                returnLength,
                &returnLength))
            {
                if (AllocateAndInitializeSid(&NtAuthority,
                    2,
                    SECURITY_BUILTIN_DOMAIN_RID,
                    DOMAIN_ALIAS_RID_ADMINS,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    &pSid))
                {
                    for (i = 0; i < ptg->GroupCount; i++) {
                        if (EqualSid(pSid, ptg->Groups[i].Sid)) {
                            bResult = TRUE;
                            break;
                        }
                    }

                    FreeSid(pSid);
                }
            }

            HeapFree(GetProcessHeap(), 0, ptg);
        }
        CloseHandle(hToken);
    }
    return bResult;
}

/*
* IsElevated
*
* Purpose:
*
* Returns TRUE if process runs elevated.
*
*/
BOOL IsElevated(
    _In_opt_ HANDLE ProcessHandle
)
{
    HANDLE hToken = NULL, processHandle = ProcessHandle;
    NTSTATUS Status;
    ULONG BytesRead = 0;
    TOKEN_ELEVATION te;

    if (ProcessHandle == NULL) {
        processHandle = GetCurrentProcess();
    }

    te.TokenIsElevated = 0;

    Status = NtOpenProcessToken(processHandle, TOKEN_QUERY, &hToken);
    if (NT_SUCCESS(Status)) {

        Status = NtQueryInformationToken(hToken, TokenElevation, &te,
            sizeof(TOKEN_ELEVATION), &BytesRead);

        NtClose(hToken);
    }

    return (te.TokenIsElevated > 0);
}

/*
* PELoaderGetProcNameBySDTIndex
*
* Purpose:
*
* Return name of service from ntdll by given syscall id.
*
*/
PCHAR PELoaderGetProcNameBySDTIndex(
    _In_ ULONG_PTR MappedImageBase,
    _In_ ULONG SDTIndex
)
{

    PIMAGE_NT_HEADERS       nthdr = RtlImageNtHeader((PVOID)MappedImageBase);
    PIMAGE_EXPORT_DIRECTORY ExportDirectory;

    ULONG_PTR   ExportDirectoryOffset;
    PULONG      NameTableBase;
    PUSHORT     NameOrdinalTableBase;
    PULONG      Addr;
    PBYTE       pfn;
    ULONG       c;

    ExportDirectoryOffset =
        nthdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    if (ExportDirectoryOffset == 0)
        return NULL;

    ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(MappedImageBase + ExportDirectoryOffset);
    NameTableBase = (PULONG)(MappedImageBase + (ULONG)ExportDirectory->AddressOfNames);
    NameOrdinalTableBase = (PUSHORT)(MappedImageBase + (ULONG)ExportDirectory->AddressOfNameOrdinals);
    Addr = (PULONG)(MappedImageBase + (ULONG)ExportDirectory->AddressOfFunctions);

    for (c = 0; c < ExportDirectory->NumberOfNames; c++) {
        pfn = (PBYTE)(MappedImageBase + Addr[NameOrdinalTableBase[c]]);
        if (*((PULONG)pfn) == 0xb8d18b4c)
            if (*((PULONG)(pfn + 4)) == SDTIndex)
                return (PCHAR)(MappedImageBase + NameTableBase[c]);
    }

    return NULL;
}

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
    _Out_ PWIN32_SHADOWTABLE* Table
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
    _In_ PWIN32_SHADOWTABLE ShadowTable
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
* FuzzFind_KiServiceTable
*
* Purpose:
*
* Locate KiServiceTable in mapped ntoskrnl copy.
*
*/
BOOL FuzzFind_KiServiceTable(
    _In_ ULONG_PTR MappedImageBase,
    _In_ PRAW_SERVICE_TABLE ServiceTable
)
{
    ULONG_PTR             SectionPtr = 0;
    IMAGE_NT_HEADERS     *NtHeaders = RtlImageNtHeader((PVOID)MappedImageBase);
    IMAGE_SECTION_HEADER *SectionTableEntry;
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
    ServiceTable->ServiceTable = (LPVOID *)(MappedImageBase + c);

    return TRUE;
}

/*
* FuzzFind_W32pServiceTable
*
* Purpose:
*
* Locate shadow table info in mapped win32k copy.
*
*/
BOOL FuzzFind_W32pServiceTable(
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

    ServiceTable->ServiceTable = (LPVOID *)GetProcAddress(MappedImageBase, "W32pServiceTable");
    if (ServiceTable->ServiceTable == NULL)
        return FALSE;

    return TRUE;
}

/*
* supHeapAlloc
*
* Purpose:
*
* Wrapper for RtlAllocateHeap.
*
*/
FORCEINLINE PVOID supHeapAlloc(
    _In_ SIZE_T Size)
{
    return RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Size);
}

/*
* supHeapFree
*
* Purpose:
*
* Wrapper for RtlFreeHeap.
*
*/
FORCEINLINE BOOL supHeapFree(
    _In_ PVOID Memory)
{
    return RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, Memory);
}

/*
* supPrivilegeEnabled
*
* Purpose:
*
* Tests if the given token has the given privilege enabled/enabled by default.
*
*/
NTSTATUS supPrivilegeEnabled(
    _In_ HANDLE ClientToken,
    _In_ ULONG Privilege,
    _Out_ PBOOLEAN pfResult
)
{
    NTSTATUS status;
    PRIVILEGE_SET Privs;
    BOOLEAN bResult = FALSE;

    Privs.Control = PRIVILEGE_SET_ALL_NECESSARY;
    Privs.PrivilegeCount = 1;
    Privs.Privilege[0].Luid.LowPart = Privilege;
    Privs.Privilege[0].Luid.HighPart = 0;
    Privs.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED_BY_DEFAULT | SE_PRIVILEGE_ENABLED;

    status = NtPrivilegeCheck(ClientToken, &Privs, &bResult);

    *pfResult = bResult;

    return status;
}

/*
* supQueryTokenUserSid
*
* Purpose:
*
* Return SID of given token.
*
* Use supHeapFree to free memory allocated for result.
*
*/
PSID supQueryTokenUserSid(
    _In_ HANDLE hProcessToken
)
{
    PSID result = NULL;
    PTOKEN_USER ptu;
    NTSTATUS status;
    ULONG SidLength = 0, Length;

    status = NtQueryInformationToken(hProcessToken, TokenUser,
        NULL, 0, &SidLength);

    if (status == STATUS_BUFFER_TOO_SMALL) {

        ptu = (PTOKEN_USER)supHeapAlloc(SidLength);

        if (ptu) {

            status = NtQueryInformationToken(hProcessToken, TokenUser,
                ptu, SidLength, &SidLength);

            if (NT_SUCCESS(status)) {
                Length = SECURITY_MAX_SID_SIZE;
                if (SidLength > Length)
                    Length = SidLength;
                result = supHeapAlloc(Length);
                if (result) {
                    status = RtlCopySid(Length, result, ptu->User.Sid);
                }
            }

            supHeapFree(ptu);
        }
    }

    return (NT_SUCCESS(status)) ? result : NULL;
}

/*
* supQueryProcessSid
*
* Purpose:
*
* Return SID for the given process.
*
* Use supHeapFree to free memory allocated for result.
*
*/
PSID supQueryProcessSid(
    _In_ HANDLE hProcess
)
{
    HANDLE hProcessToken = NULL;
    PSID result = NULL;

    if (NT_SUCCESS(NtOpenProcessToken(hProcess, TOKEN_QUERY, &hProcessToken))) {

        result = supQueryTokenUserSid(hProcessToken);

        NtClose(hProcessToken);
    }

    return result;
}

/*
* supIsLocalSystem
*
* Purpose:
*
* pbResult will be set to TRUE if current account is run by system user, FALSE otherwise.
*
* Function return operation status code.
*
*/
NTSTATUS supIsLocalSystem(
    _In_ HANDLE hToken,
    _Out_ PBOOLEAN pbResult)
{
    BOOLEAN                  bResult = FALSE;
    NTSTATUS                 status = STATUS_UNSUCCESSFUL;
    PSID                     SystemSid = NULL, TokenSid = NULL;
    SID_IDENTIFIER_AUTHORITY NtAuth = SECURITY_NT_AUTHORITY;

    TokenSid = supQueryTokenUserSid(hToken);
    if (TokenSid == NULL)
        return status;

    status = RtlAllocateAndInitializeSid(
        &NtAuth,
        1,
        SECURITY_LOCAL_SYSTEM_RID,
        0, 0, 0, 0, 0, 0, 0,
        &SystemSid);

    if (NT_SUCCESS(status)) {
        bResult = RtlEqualSid(TokenSid, SystemSid);
        RtlFreeSid(SystemSid);
    }

    supHeapFree(TokenSid);

    if (pbResult)
        *pbResult = bResult;

    return status;
}

/*
* supOpenProcess
*
* Purpose:
*
* NtOpenProcess wrapper.
*
*/
NTSTATUS supOpenProcess(
    _In_ HANDLE UniqueProcessId,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE ProcessHandle
)
{
    NTSTATUS Status;
    HANDLE Handle = NULL;
    OBJECT_ATTRIBUTES ObjectAttributes = RTL_INIT_OBJECT_ATTRIBUTES((PUNICODE_STRING)NULL, 0);
    CLIENT_ID ClientId;

    ClientId.UniqueProcess = UniqueProcessId;
    ClientId.UniqueThread = NULL;

    Status = NtOpenProcess(&Handle, DesiredAccess, &ObjectAttributes, &ClientId);

    if (NT_SUCCESS(Status)) {
        *ProcessHandle = Handle;
    }

    return Status;
}

/*
* supxGetSystemToken
*
* Purpose:
*
* Find winlogon process and duplicate it token.
*
*/
NTSTATUS supxGetSystemToken(
    _In_ PVOID ProcessList,
    _Out_ PHANDLE SystemToken)
{
    BOOLEAN bSystemToken = FALSE, bEnabled = FALSE;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    ULONG NextEntryDelta = 0;
    HANDLE hObject = NULL;
    HANDLE hToken = NULL;

    ULONG WinlogonSessionId;
    UNICODE_STRING usWinlogon = RTL_CONSTANT_STRING(L"winlogon.exe");

    union {
        PSYSTEM_PROCESSES_INFORMATION Processes;
        PBYTE ListRef;
    } List;

    *SystemToken = NULL;

    WinlogonSessionId = WTSGetActiveConsoleSessionId();
    if (WinlogonSessionId == 0xFFFFFFFF)
        return STATUS_INVALID_SESSION;

    List.ListRef = (PBYTE)ProcessList;

    do {

        List.ListRef += NextEntryDelta;

        if (RtlEqualUnicodeString(&usWinlogon, &List.Processes->ImageName, TRUE)) {

            if (List.Processes->SessionId == WinlogonSessionId) {

                Status = supOpenProcess(
                    List.Processes->UniqueProcessId,
                    PROCESS_QUERY_LIMITED_INFORMATION,
                    &hObject);

                if (NT_SUCCESS(Status)) {

                    Status = NtOpenProcessToken(
                        hObject,
                        TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_IMPERSONATE | TOKEN_QUERY,
                        &hToken);

                    if (NT_SUCCESS(Status)) {

                        Status = supIsLocalSystem(hToken, &bSystemToken);

                        if (NT_SUCCESS(Status) && (bSystemToken)) {

                            Status = supPrivilegeEnabled(hToken, SE_TCB_PRIVILEGE, &bEnabled);
                            if (NT_SUCCESS(Status)) {
                                if (bEnabled) {
                                    NtClose(hObject);
                                    *SystemToken = hToken;
                                    return STATUS_SUCCESS;
                                }
                                else {
                                    Status = STATUS_PRIVILEGE_NOT_HELD;
                                }
                            }
                        }
                        NtClose(hToken);
                    }

                    NtClose(hObject);
                }

            }
        }

        NextEntryDelta = List.Processes->NextEntryDelta;

    } while (NextEntryDelta);

    return Status;
}

/*
* supShowNtStatus
*
* Purpose:
*
* Display detailed last nt status to user.
*
*/
VOID supShowNtStatus(
    _In_ LPCSTR lpText,
    _In_ NTSTATUS Status
)
{
    PCHAR lpMsg;
    SIZE_T Length = _strlen_a(lpText);
    lpMsg = (PCHAR)supHeapAlloc(Length + 200);
    if (lpMsg) {
        _strcpy_a(lpMsg, "[!] ");
        _strcat_a(lpMsg, lpText);
        ultohex_a((ULONG)Status, _strend_a(lpMsg));
        _strcat_a(lpMsg, "\r\n");
        FuzzShowMessage(lpMsg, FOREGROUND_RED | FOREGROUND_INTENSITY);
        supHeapFree(lpMsg);
    }
}

/*
* supGetSystemInfo
*
* Purpose:
*
* Returns buffer with system information by given InfoClass.
*
* Returned buffer must be freed with supHeapFree after usage.
* Function will return error after 20 attempts.
*
*/
PVOID supGetSystemInfo(
    _In_ SYSTEM_INFORMATION_CLASS InfoClass
)
{
    INT			c = 0;
    PVOID		Buffer = NULL;
    ULONG		Size = PAGE_SIZE;
    NTSTATUS	status;
    ULONG       memIO;

    do {
        Buffer = supHeapAlloc((SIZE_T)Size);
        if (Buffer != NULL) {
            status = NtQuerySystemInformation(InfoClass, Buffer, Size, &memIO);
        }
        else {
            return NULL;
        }
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            supHeapFree(Buffer);
            Buffer = NULL;
            Size *= 2;
            c++;
            if (c > 20) {
                status = STATUS_SECRET_TOO_LONG;
                break;
            }
        }
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (NT_SUCCESS(status)) {
        return Buffer;
    }

    if (Buffer) {
        supHeapFree(Buffer);
    }
    return NULL;
}

/*
* supEnablePrivilege
*
* Purpose:
*
* Enable/Disable given privilege.
*
* Return FALSE on any error.
*
*/
BOOL supEnablePrivilege(
    _In_ DWORD PrivilegeName,
    _In_ BOOL fEnable
)
{
    BOOL             bResult = FALSE;
    NTSTATUS         status;
    ULONG            dummy;
    HANDLE           hToken;
    TOKEN_PRIVILEGES TokenPrivileges;

    status = NtOpenProcessToken(
        NtCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        &hToken);

    if (!NT_SUCCESS(status)) {
        return bResult;
    }

    TokenPrivileges.PrivilegeCount = 1;
    TokenPrivileges.Privileges[0].Luid.LowPart = PrivilegeName;
    TokenPrivileges.Privileges[0].Luid.HighPart = 0;
    TokenPrivileges.Privileges[0].Attributes = (fEnable) ? SE_PRIVILEGE_ENABLED : 0;
    status = NtAdjustPrivilegesToken(hToken, FALSE, &TokenPrivileges,
        sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PULONG)&dummy);
    if (status == STATUS_NOT_ALL_ASSIGNED) {
        status = STATUS_PRIVILEGE_NOT_HELD;
    }
    bResult = NT_SUCCESS(status);
    NtClose(hToken);
    return bResult;
}

/*
* RunAsLocalSystem
*
* Purpose:
*
* Restart program in local system account.
*
* Note: Elevated instance required.
*
*/
VOID RunAsLocalSystem(
    VOID
)
{
    BOOL bSuccess = FALSE;
    NTSTATUS Status;
    PVOID ProcessList;
    ULONG SessionId = NtCurrentPeb()->SessionId, dummy;

    HANDLE hSystemToken = NULL, hPrimaryToken = NULL, hImpersonationToken = NULL;

    BOOLEAN bThreadImpersonated = FALSE;

    PROCESS_INFORMATION pi;
    STARTUPINFO si;

    SECURITY_QUALITY_OF_SERVICE sqos;
    OBJECT_ATTRIBUTES obja;
    TOKEN_PRIVILEGES *TokenPrivileges;

    WCHAR szApplication[MAX_PATH * 2];

    //
    // Remember our application name.
    //
    RtlSecureZeroMemory(szApplication, sizeof(szApplication));
    GetModuleFileName(NULL, szApplication, MAX_PATH);

    sqos.Length = sizeof(sqos);
    sqos.ImpersonationLevel = SecurityImpersonation;
    sqos.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
    sqos.EffectiveOnly = FALSE;
    InitializeObjectAttributes(&obja, NULL, 0, NULL, NULL);
    obja.SecurityQualityOfService = &sqos;

    ProcessList = supGetSystemInfo(SystemProcessInformation);
    if (ProcessList == NULL) {
        return;
    }

    //
    // Optionally, enable debug privileges.
    // 
    supEnablePrivilege(SE_DEBUG_PRIVILEGE, TRUE);

    //
    // Get LocalSystem token from winlogon.
    //
    Status = supxGetSystemToken(ProcessList, &hSystemToken);

    supHeapFree(ProcessList);

    do {
        //
        // Check supxGetSystemToken result.
        //
        if (!NT_SUCCESS(Status) || (hSystemToken == NULL)) {

            supShowNtStatus(
                "No suitable system token found. Make sure you are running as administrator, code 0x",
                Status);

            break;
        }

        //
        // Duplicate as impersonation token.
        //
        Status = NtDuplicateToken(
            hSystemToken,
            TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY |
            TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_PRIVILEGES,
            &obja,
            FALSE,
            TokenImpersonation,
            &hImpersonationToken);

        if (!NT_SUCCESS(Status)) {

            supShowNtStatus("Error duplicating impersonation token, code 0x", Status);
            break;
        }

        //
        // Duplicate as primary token.
        //
        Status = NtDuplicateToken(
            hSystemToken,
            TOKEN_ALL_ACCESS,
            &obja,
            FALSE,
            TokenPrimary,
            &hPrimaryToken);

        if (!NT_SUCCESS(Status)) {

            supShowNtStatus("Error duplicating primary token, code 0x", Status);
            break;
        }

        //
        // Impersonate system token.
        //
        Status = NtSetInformationThread(
            NtCurrentThread(),
            ThreadImpersonationToken,
            &hImpersonationToken,
            sizeof(HANDLE));

        if (!NT_SUCCESS(Status)) {

            supShowNtStatus("Error while impersonating primary token, code 0x", Status);
            break;
        }

        bThreadImpersonated = TRUE;

        //
        // Turn on AssignPrimaryToken privilege in impersonated token.
        //
        TokenPrivileges = (TOKEN_PRIVILEGES*)_alloca(sizeof(TOKEN_PRIVILEGES) +
            (1 * sizeof(LUID_AND_ATTRIBUTES)));

        TokenPrivileges->PrivilegeCount = 1;
        TokenPrivileges->Privileges[0].Luid.LowPart = SE_ASSIGNPRIMARYTOKEN_PRIVILEGE;
        TokenPrivileges->Privileges[0].Luid.HighPart = 0;
        TokenPrivileges->Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        Status = NtAdjustPrivilegesToken(
            hImpersonationToken,
            FALSE,
            TokenPrivileges,
            0,
            NULL,
            (PULONG)&dummy);

        if (!NT_SUCCESS(Status)) {
            supShowNtStatus("Error adjusting token privileges, code 0x", Status);
            break;
        }

        //
        // Set session id to primary token.
        //
        Status = NtSetInformationToken(
            hPrimaryToken,
            TokenSessionId,
            &SessionId,
            sizeof(ULONG));

        if (!NT_SUCCESS(Status)) {
            supShowNtStatus("Error setting session id, code 0x", Status);
            break;
        }

        si.cb = sizeof(si);
        GetStartupInfo(&si);

        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_SHOWNORMAL;

        //
        // Run new instance with prepared primary token.
        //
        bSuccess = CreateProcessAsUser(
            hPrimaryToken,
            szApplication,
            GetCommandLine(),
            NULL,
            NULL,
            FALSE,
            CREATE_DEFAULT_ERROR_MODE,
            NULL,
            NULL,
            &si,
            &pi);

        if (bSuccess) {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
        else {
            supShowNtStatus("Run as LocalSystem, code 0x", GetLastError());
        }

    } while (FALSE);

    if (hImpersonationToken) {
        NtClose(hImpersonationToken);
    }

    //
    // Revert To Self.
    //
    if (bThreadImpersonated) {
        hImpersonationToken = NULL;
        NtSetInformationThread(
            NtCurrentThread(),
            ThreadImpersonationToken,
            (PVOID)&hImpersonationToken,
            sizeof(HANDLE));
    }

    if (hPrimaryToken) NtClose(hPrimaryToken);
    if (hSystemToken) NtClose(hSystemToken);

    //
    // Quit.
    //
    if (bSuccess)
        PostQuitMessage(0);
}

/*
* supGetCurrentProcessToken
*
* Purpose:
*
* Return current process token value with TOKEN_QUERY access right.
*
*/
HANDLE supGetCurrentProcessToken(
    VOID)
{
    HANDLE hToken = NULL;

    if (NT_SUCCESS(NtOpenProcessToken(
        NtCurrentProcess(),
        TOKEN_QUERY,
        &hToken)))
    {
        return hToken;
    }
    return NULL;
}

/*
* IsLocalSystem
*
* Purpose:
*
* Returns TRUE if current user is LocalSystem.
*
*/
BOOLEAN IsLocalSystem()
{
    BOOLEAN bResult = FALSE;
    HANDLE hToken;

    hToken = supGetCurrentProcessToken();
    if (hToken) {
        supIsLocalSystem(hToken, &bResult);
        NtClose(hToken);
    }

    return bResult;
}
