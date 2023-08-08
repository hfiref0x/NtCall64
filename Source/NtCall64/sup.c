/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2023
*
*  TITLE:       SUP.C
*
*  VERSION:     1.37
*
*  DATE:        04 Aug 2023
*
*  Support routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

VOID ConsoleInit(
    VOID)
{
    COORD coordScreen = { 0, 0 };
    DWORD cCharsWritten;
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    DWORD dwConSize;
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    if (!GetConsoleScreenBufferInfo(hConsole, &csbi))
        return;

    SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED);

    dwConSize = csbi.dwSize.X * csbi.dwSize.Y;

    if (!FillConsoleOutputCharacter(hConsole, (TCHAR)' ',
        dwConSize, coordScreen, &cCharsWritten))
        return;

    if (!GetConsoleScreenBufferInfo(hConsole, &csbi))
        return;

    if (!FillConsoleOutputAttribute(hConsole, csbi.wAttributes,
        dwConSize, coordScreen, &cCharsWritten))
        return;

    SetConsoleCursorPosition(hConsole, coordScreen);
}

/*
* ConsoleShowMessage
*
* Purpose:
*
* Output text to screen.
*
*/
VOID ConsoleShowMessage(
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
* supGetCommandLineOption
*
* Purpose:
*
* Parse command line options.
*
*/
BOOLEAN supGetCommandLineOption(
    _In_ LPCWSTR OptionName,
    _In_ BOOLEAN IsParametric,
    _Out_writes_opt_z_(ValueSize) LPWSTR OptionValue,
    _In_ ULONG ValueSize,
    _Out_opt_ PULONG ParamLength
)
{
    BOOLEAN bResult;
    LPWSTR cmdline = GetCommandLine();
    WCHAR szParam[MAX_PATH + 1];
    ULONG rlen;
    INT	i = 0;

    if (ParamLength)
        *ParamLength = 0;

    RtlSecureZeroMemory(szParam, sizeof(szParam));
    while (GetCommandLineParam(
        cmdline, 
        i, 
        szParam, 
        MAX_PATH, 
        &rlen)) 
    {
        if (rlen == 0)
            break;

        if (_strcmp(szParam, OptionName) == 0) {
            if (IsParametric) {
                bResult = (BOOLEAN)GetCommandLineParam(cmdline, i + 1, OptionValue, ValueSize, &rlen);
                if (ParamLength)
                    *ParamLength = rlen;
                return bResult;
            }

            return TRUE;
        }
        ++i;
    }

    return FALSE;
}

/*
* supUserIsFullAdmin
*
* Purpose:
*
* Tests if the current user is admin with full access token.
*
*/
BOOLEAN supUserIsFullAdmin(
    _In_ HANDLE hToken
)
{
    BOOLEAN bResult = FALSE;
    NTSTATUS status;
    DWORD i, Attributes;
    ULONG ReturnLength = 0;

    PTOKEN_GROUPS pTkGroups;

    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID adminGroup = NULL;

    do {
        if (!NT_SUCCESS(RtlAllocateAndInitializeSid(
            &ntAuthority,
            2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0,
            &adminGroup)))
        {
            break;
        }

        status = NtQueryInformationToken(hToken, TokenGroups, NULL, 0, &ReturnLength);
        if (status != STATUS_BUFFER_TOO_SMALL)
            break;

        pTkGroups = (PTOKEN_GROUPS)supHeapAlloc((SIZE_T)ReturnLength);
        if (pTkGroups == NULL)
            break;

        status = NtQueryInformationToken(hToken, TokenGroups, pTkGroups, ReturnLength, &ReturnLength);
        if (NT_SUCCESS(status)) {
            if (pTkGroups->GroupCount > 0)
                for (i = 0; i < pTkGroups->GroupCount; i++) {
                    Attributes = pTkGroups->Groups[i].Attributes;
                    if (RtlEqualSid(adminGroup, pTkGroups->Groups[i].Sid))
                        if (
                            (Attributes & SE_GROUP_ENABLED) &&
                            (!(Attributes & SE_GROUP_USE_FOR_DENY_ONLY))
                            )
                        {
                            bResult = TRUE;
                            break;
                        }
                }
        }
        supHeapFree(pTkGroups);

    } while (FALSE);

    if (adminGroup != NULL) {
        RtlFreeSid(adminGroup);
    }

    return bResult;
}

/*
* supIsClientElevated
*
* Purpose:
*
* Returns TRUE if process runs elevated.
*
*/
BOOLEAN supIsClientElevated(
    _In_ HANDLE ProcessHandle
)
{
    HANDLE hToken = NULL, processHandle = ProcessHandle;
    NTSTATUS Status;
    ULONG BytesRead = 0;
    TOKEN_ELEVATION te;

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
* supLdrGetProcNameBySDTIndex
*
* Purpose:
*
* Return name of service from ntdll by given syscall id.
*
*/
PCHAR supLdrGetProcNameBySDTIndex(
    _In_ PVOID ModuleBase,
    _In_ ULONG SDTIndex
)
{
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory;
    PULONG nameTableBase;
    PUSHORT nameOrdinalTableBase;
    PULONG funcTable;
    PBYTE pfn;
    ULONG c, exportSize;

    pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RtlImageDirectoryEntryToData(ModuleBase,
        TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &exportSize);

    if (pImageExportDirectory) {

        nameTableBase = (PDWORD)RtlOffsetToPointer(ModuleBase, pImageExportDirectory->AddressOfNames);
        nameOrdinalTableBase = (PUSHORT)RtlOffsetToPointer(ModuleBase, pImageExportDirectory->AddressOfNameOrdinals);
        funcTable = (PDWORD)RtlOffsetToPointer(ModuleBase, pImageExportDirectory->AddressOfFunctions);

        for (c = 0; c < pImageExportDirectory->NumberOfNames; c++) {
            pfn = (PBYTE)RtlOffsetToPointer(ModuleBase, funcTable[nameOrdinalTableBase[c]]);
            if (*((PULONG)pfn) == 0xb8d18b4c)
                if (*((PULONG)(pfn + 4)) == SDTIndex)
                    return (PCHAR)RtlOffsetToPointer(ModuleBase, nameTableBase[c]);
        }

    }

    return NULL;
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
    BOOLEAN bResult = FALSE;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PSID SystemSid = NULL, TokenSid = NULL;
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
        ConsoleShowMessage(lpMsg, FOREGROUND_RED | FOREGROUND_INTENSITY);
        supHeapFree(lpMsg);
    }
}

#define SI_MAX_BUFFER_LENGTH (512 * 1024 * 1024)

/*
* supGetSystemInfo
*
* Purpose:
*
* Returns buffer with system information by given InfoClass.
*
* Returned buffer must be freed with supHeapFree after usage.
*
*/
PVOID supGetSystemInfo(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass
)
{
    PVOID       buffer = NULL;
    ULONG       bufferSize = PAGE_SIZE;
    NTSTATUS    ntStatus;
    ULONG       returnedLength = 0;

    buffer = supHeapAlloc((SIZE_T)bufferSize);
    if (buffer == NULL)
        return NULL;

    while ((ntStatus = NtQuerySystemInformation(
        SystemInformationClass,
        buffer,
        bufferSize,
        &returnedLength)) == STATUS_INFO_LENGTH_MISMATCH)
    {
        supHeapFree(buffer);
        bufferSize <<= 1;

        if (bufferSize > SI_MAX_BUFFER_LENGTH)
            return NULL;

        buffer = supHeapAlloc((SIZE_T)bufferSize);
    }

    if (NT_SUCCESS(ntStatus)) {
        return buffer;
    }

    if (buffer)
        supHeapFree(buffer);

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
    NTSTATUS status;
    ULONG dummy;
    HANDLE hToken;
    TOKEN_PRIVILEGES tkPrivs;

    status = NtOpenProcessToken(
        NtCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        &hToken);

    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    tkPrivs.PrivilegeCount = 1;
    tkPrivs.Privileges[0].Luid.LowPart = PrivilegeName;
    tkPrivs.Privileges[0].Luid.HighPart = 0;
    tkPrivs.Privileges[0].Attributes = (fEnable) ? SE_PRIVILEGE_ENABLED : 0;
    status = NtAdjustPrivilegesToken(hToken, FALSE, &tkPrivs,
        sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PULONG)&dummy);
    if (status == STATUS_NOT_ALL_ASSIGNED) {
        status = STATUS_PRIVILEGE_NOT_HELD;
    }
    NtClose(hToken);
    return NT_SUCCESS(status);
}

/*
* supRunAsLocalSystem
*
* Purpose:
*
* Restart program in local system account.
*
* Note: Elevated instance required.
*
*/
VOID supRunAsLocalSystem(
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
    TOKEN_PRIVILEGES* TokenPrivileges;

    BYTE TokenPrivBufffer[sizeof(TOKEN_PRIVILEGES) +
        (1 * sizeof(LUID_AND_ATTRIBUTES))];

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
        TokenPrivileges = (TOKEN_PRIVILEGES*)&TokenPrivBufffer;
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
* supMapImageNoExecute
*
* Purpose:
*
* Map image with SEC_IMAGE_NO_EXECUTE.
*
*/
NTSTATUS supMapImageNoExecute(
    _In_ PUNICODE_STRING ImagePath,
    _Out_ PVOID* BaseAddress
)
{
    NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
    SIZE_T fileSize = 0;
    HANDLE hFile = NULL, hSection = NULL;
    OBJECT_ATTRIBUTES obja;
    IO_STATUS_BLOCK iost;
    LARGE_INTEGER li;

    *BaseAddress = NULL;

    do {

        InitializeObjectAttributes(&obja, ImagePath,
            OBJ_CASE_INSENSITIVE, NULL, NULL);

        RtlSecureZeroMemory(&iost, sizeof(iost));
        ntStatus = NtCreateFile(&hFile,
            SYNCHRONIZE | FILE_READ_DATA,
            &obja,
            &iost,
            NULL,
            0,
            FILE_SHARE_READ,
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
            NULL,
            0);

        if (!NT_SUCCESS(ntStatus))
            break;

        obja.ObjectName = NULL;

        ntStatus = NtCreateSection(&hSection,
            SECTION_MAP_READ,
            &obja,
            NULL,
            PAGE_READONLY,
            SEC_IMAGE_NO_EXECUTE,
            hFile);

        if (!NT_SUCCESS(ntStatus))
            break;

        li.QuadPart = 0;

        ntStatus = NtMapViewOfSection(hSection,
            NtCurrentProcess(),
            BaseAddress,
            0,
            0,
            &li,
            &fileSize,
            ViewShare,
            0,
            PAGE_READONLY);

        if (!NT_SUCCESS(ntStatus))
            break;

    } while (FALSE);

    if (hFile) NtClose(hFile);
    if (hSection) NtClose(hSection);
    return ntStatus;
}

/*
* supLdrGetProcAddressEx
*
* Purpose:
*
* Simplified GetProcAddress reimplementation.
*
*/
LPVOID supLdrGetProcAddressEx(
    _In_ LPVOID ImageBase,
    _In_ LPCSTR RoutineName
)
{
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
    USHORT OrdinalNumber;
    PULONG NameTableBase;
    PUSHORT NameOrdinalTableBase;
    PULONG Addr;
    LONG Result;
    ULONG High, Low, Middle = 0;

    union {
        PIMAGE_NT_HEADERS64 nt64;
        PIMAGE_NT_HEADERS32 nt32;
        PIMAGE_NT_HEADERS nt;
    } NtHeaders;

    if (!NT_SUCCESS(RtlImageNtHeaderEx(RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK,
        ImageBase, 0, &NtHeaders.nt)))
    {
        return NULL;
    }

    if (NtHeaders.nt == NULL) {
        return NULL;
    }

    if (NtHeaders.nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {

        ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RtlOffsetToPointer(ImageBase,
            NtHeaders.nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    }
    else if (NtHeaders.nt->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {

        ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RtlOffsetToPointer(ImageBase,
            NtHeaders.nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    }
    else
    {
        return NULL;
    }

    NameTableBase = (PULONG)RtlOffsetToPointer(ImageBase, (ULONG)ExportDirectory->AddressOfNames);
    NameOrdinalTableBase = (PUSHORT)RtlOffsetToPointer(ImageBase, (ULONG)ExportDirectory->AddressOfNameOrdinals);
    Low = 0;
    High = ExportDirectory->NumberOfNames - 1;
    while (High >= Low) {

        Middle = (Low + High) >> 1;

        Result = _strcmp_a(
            RoutineName,
            (char*)RtlOffsetToPointer(ImageBase, NameTableBase[Middle]));

        if (Result < 0) {
            High = Middle - 1;
        }
        else {
            if (Result > 0) {
                Low = Middle + 1;
            }
            else {
                break;
            }
        }
    }
    if (High < Low)
        return NULL;

    OrdinalNumber = NameOrdinalTableBase[Middle];
    if ((ULONG)OrdinalNumber >= ExportDirectory->NumberOfFunctions)
        return NULL;

    Addr = (PULONG)RtlOffsetToPointer(ImageBase, (ULONG)ExportDirectory->AddressOfFunctions);
    return (LPVOID)RtlOffsetToPointer(ImageBase, Addr[OrdinalNumber]);
}
