/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2019
*
*  TITLE:       UTIL.C
*
*  VERSION:     1.31
*
*  DATE:        03 May 2019
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
    BOOL    bCond = FALSE, bResult = FALSE;
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

    } while (bCond);

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
    ULONG returnLength;
    HANDLE hToken;
    TOKEN_USER *ptu;

    PSID pSid;

    BYTE TokenInformation[256];

    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        if (GetTokenInformation(hToken, TokenUser, &TokenInformation,
            sizeof(TokenInformation), &returnLength))
        {

            if (AllocateAndInitializeSid(&NtAuthority,
                1,
                SECURITY_LOCAL_SYSTEM_RID,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                &pSid))
            {
                ptu = (PTOKEN_USER)&TokenInformation;

                bResult = (EqualSid(pSid, ptu->User.Sid) != 0);

                FreeSid(pSid);
            }

        }

        CloseHandle(hToken);
    }

    return bResult;
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
* PELoaderIATEntryToImport
*
* Purpose:
*
* Resolve function name.
*
*/
_Success_(return != NULL)
LPCSTR PELoaderIATEntryToImport(
    _In_ LPVOID Module,
    _In_ LPVOID IATEntry,
    _Out_opt_ LPCSTR *ImportModuleName
)
{
    PIMAGE_NT_HEADERS           NtHeaders;
    PIMAGE_IMPORT_DESCRIPTOR    impd;
    ULONG_PTR                   *rname, imprva;
    LPVOID                      *raddr;

    NtHeaders = RtlImageNtHeader(Module);
    if (NtHeaders->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_IMPORT)
        return NULL;

    imprva = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (imprva == 0)
        return NULL;

    impd = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)Module + imprva);

    while (impd->Name != 0) {
        raddr = (LPVOID *)((ULONG_PTR)Module + impd->FirstThunk);
        if (impd->OriginalFirstThunk == 0)
            rname = (ULONG_PTR *)raddr;
        else
            rname = (ULONG_PTR *)((ULONG_PTR)Module + impd->OriginalFirstThunk);

        while (*rname != 0) {
            if (IATEntry == raddr)
            {
                if (((*rname) & IMAGE_ORDINAL_FLAG) == 0)
                {
                    if (ImportModuleName) {
                        *ImportModuleName = (LPCSTR)((ULONG_PTR)Module + impd->Name);
                    }
                    return (LPCSTR)&((PIMAGE_IMPORT_BY_NAME)((ULONG_PTR)Module + *rname))->Name;
                }
            }

            ++rname;
            ++raddr;
        }
        ++impd;
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
