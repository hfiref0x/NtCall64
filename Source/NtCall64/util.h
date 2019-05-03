/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2019
*
*  TITLE:       UTIL.H
*
*  VERSION:     1.31
*
*  DATE:        03 May 2019
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

typedef struct _BL_ENTRY {
    LIST_ENTRY ListEntry;
    DWORD Hash;
} BL_ENTRY, *PBL_ENTRY;

typedef struct _BLACKLIST {
    HANDLE HeapHandle;
    ULONG NumberOfEntries;
    LIST_ENTRY ListHead;
} BLACKLIST, *PBLACKLIST;

#define CFG_FILE    "badcalls.ini"

DWORD BlackListHashString(
    _In_ LPCSTR Name);

BOOL BlackListCreateFromFile(
    _In_ BLACKLIST *BlackList,
    _In_ LPCSTR ConfigFileName,
    _In_ LPCSTR ConfigSectionName);

BOOL BlackListEntryPresent(
    _In_ BLACKLIST *BlackList,
    _In_ LPCSTR SyscallName);

VOID BlackListDestroy(
    _In_ BLACKLIST *BlackList);

BOOL GetImageVersionInfo(
    _In_ LPWSTR lpFileName,
    _Out_opt_ ULONG *MajorVersion,
    _Out_opt_ ULONG *MinorVersion,
    _Out_opt_ ULONG *Build,
    _Out_opt_ ULONG *Revision);

VOID FuzzShowMessage(
    _In_ LPCSTR lpMessage,
    _In_opt_ WORD wColor);

BOOL GetCommandLineOption(
    _In_ LPCTSTR OptionName,
    _In_ BOOL IsParametric,
    _Out_writes_opt_z_(ValueSize) LPTSTR OptionValue,
    _In_ ULONG ValueSize);

BOOL FuzzOpenLog(
    _Out_ PHANDLE LogHandle,
    _Out_opt_ PDWORD LastError);

VOID FuzzCloseLog(
    _Inout_ PHANDLE LogHandle);

VOID FuzzLogCallName(
    _In_ HANDLE LogHandle,
    _In_ LPCSTR ServiceName);

VOID FuzzLogCallParameters(
    _In_ HANDLE LogHandle,
    _In_ ULONG ServiceId,
    _In_ ULONG NumberOfArguments,
    _In_ ULONG_PTR *Arguments);

BOOL FuzzFind_KiServiceTable(
    _In_ ULONG_PTR MappedImageBase,
    _In_ PRAW_SERVICE_TABLE ServiceTable);

BOOL FuzzFind_W32pServiceTable(
    _In_ HMODULE MappedImageBase,
    _In_ PRAW_SERVICE_TABLE ServiceTable);

BOOLEAN IsLocalSystem();
BOOLEAN IsUserInAdminGroup();

BOOL IsElevated(
    _In_opt_ HANDLE ProcessHandle);

PCHAR PELoaderGetProcNameBySDTIndex(
    _In_ ULONG_PTR MappedImageBase,
    _In_ ULONG SDTIndex);

_Success_(return != NULL)
LPCSTR PELoaderIATEntryToImport(
    _In_ LPVOID Module,
    _In_ LPVOID IATEntry,
    _Out_opt_ LPCSTR *ImportModuleName);
