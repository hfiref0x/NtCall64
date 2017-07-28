/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2017
*
*  TITLE:       UTIL.C
*
*  VERSION:     1.20
*
*  DATE:        28 July 2017
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

/*
* force_priv
*
* Purpose:
*
* Attempt to enable all known privileges.
*
*/
void force_priv()
{
    ULONG c;
    BOOLEAN bWasEnabled;

    for (c = SE_MIN_WELL_KNOWN_PRIVILEGE; c <= SE_MAX_WELL_KNOWN_PRIVILEGE; c++) {
        RtlAdjustPrivilege(c, TRUE, FALSE, &bWasEnabled);
    }
}

/*
* log_call
*
* Purpose:
*
* Save syscall information to the log file.
*
*/
void log_call(
    ULONG ServiceNumber,
    ULONG ParametersInStack,
    ULONG_PTR *Parameters
)
{
    ULONG               i;
    NTSTATUS            Status;
    HANDLE              hLogFile = NULL;
    LARGE_INTEGER       Position;
    IO_STATUS_BLOCK     IoStatus;
    OBJECT_ATTRIBUTES   attr;
    UNICODE_STRING      NtFileName;

    CHAR                szLog[2048];

    if (RtlDosPathNameToNtPathName_U(L"fuzz.log", &NtFileName, NULL, NULL) == FALSE)
        return;

    InitializeObjectAttributes(&attr, &NtFileName, OBJ_CASE_INSENSITIVE, 0, NULL);
    Status = NtCreateFile(&hLogFile, FILE_GENERIC_WRITE, &attr,
        &IoStatus, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);

    if (NT_SUCCESS(Status)) {
        RtlSecureZeroMemory(szLog, sizeof(szLog));

        _strcpy_a(szLog, "Service: ");
        ultostr_a(ServiceNumber, _strend_a(szLog));
        _strcat_a(szLog, " ParamInStack: ");
        ultostr_a(ParametersInStack, _strend_a(szLog));
        _strcat_a(szLog, " Params:");

        for (i = 0; i < (ParametersInStack + 4); i++) {
            _strcat_a(szLog, " ");
            u64tohex_a(Parameters[i], _strend_a(szLog));
        }
        _strcat_a(szLog, "\r\n");

        Position.LowPart = FILE_WRITE_TO_END_OF_FILE;
        Position.HighPart = -1;

        NtWriteFile(hLogFile, 0, NULL, NULL, &IoStatus, szLog, (ULONG)_strlen_a(szLog), &Position, NULL);

        NtFlushBuffersFile(hLogFile, &IoStatus);
        NtClose(hLogFile);
    }
    RtlFreeUnicodeString(&NtFileName);
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
* ReadBlacklistCfg
*
* Purpose:
*
* Read blacklist from ini file.
*
*/
BOOL ReadBlacklistCfg(
    BADCALLS *Cfg,
    LPSTR CfgFileName,
    LPSTR CfgSection
)
{
    BOOL    bCond = FALSE, bResult = FALSE;
    LPSTR   Section = NULL, ptr = NULL;
    PCHAR  *Syscalls;
    ULONG   nSize = 16 * 1024, i, c;
    CHAR    ConfigFilePath[MAX_PATH + 16];

    do {

        if ((Cfg == NULL) || (CfgFileName == NULL) || (CfgSection == NULL))
            break;

        RtlSecureZeroMemory(ConfigFilePath, sizeof(ConfigFilePath));
        GetModuleFileNameA(NULL, (LPSTR)&ConfigFilePath, MAX_PATH);
        _filepath_a(ConfigFilePath, ConfigFilePath);
        _strcat_a(ConfigFilePath, CfgFileName);

        Section = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, nSize);
        if (Section == NULL)
            break;

        if (!GetPrivateProfileSectionA(CfgSection, Section, nSize, ConfigFilePath))
            break;

        ptr = Section;

        c = 0;

        do {
            if (*ptr == 0)
                break;
            ptr += _strlen_a(ptr) + 1;
            c += 1;
        } while (1);

        Syscalls = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PVOID) * c);
        if (Syscalls == NULL)
            break;

        i = 0;
        ptr = Section;
        do {
            if (*ptr == 0)
                break;
            Syscalls[i] = ptr;
            ptr += _strlen_a(ptr) + 1;
            i++;
        } while (1);

        Cfg->Count = c;
        Cfg->Syscalls = Syscalls;

        bResult = TRUE;

    } while (bCond);

    return bResult;
}

/*
* SyscallBlacklisted
*
* Purpose:
*
* Return TRUE if syscall is in blacklist.
*
*/
BOOL SyscallBlacklisted(
    LPSTR Syscall,
    BADCALLS *Cfg
)
{
    ULONG  i, c;

    if ((Cfg == NULL) || (Syscall == NULL))
        return FALSE;

    c = Cfg->Count;

    for (i = 0; i < c; i++) {
        if (_strcmp_a(Syscall, Cfg->Syscalls[i]) == 0)
            return TRUE;
    }
    return FALSE;
}

/*
* OutputConsoleMessage
*
* Purpose:
*
* Output text to screen.
*
*/
VOID OutputConsoleMessage(
    _In_ LPCSTR lpMessage)
{
    ULONG r;

    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), 
        lpMessage, 
        (DWORD)_strlen_a(lpMessage), 
        &r, 
        NULL);
}
