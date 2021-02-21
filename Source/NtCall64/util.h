/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2021
*
*  TITLE:       UTIL.H
*
*  VERSION:     1.35
*
*  DATE:        21 Feb 2021
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

typedef struct _WIN32_SHADOWTABLE {
    ULONG Index;
    CHAR Name[256];
    struct _WIN32_SHADOWTABLE *NextService;
} WIN32_SHADOWTABLE, *PWIN32_SHADOWTABLE;

BOOL GetImageVersionInfo(
    _In_ LPWSTR lpFileName,
    _Out_opt_ ULONG *MajorVersion,
    _Out_opt_ ULONG *MinorVersion,
    _Out_opt_ ULONG *Build,
    _Out_opt_ ULONG *Revision);

VOID ConsoleInit(
    VOID);

VOID ConsoleShowMessage(
    _In_ LPCSTR lpMessage,
    _In_opt_ WORD wColor);

BOOL GetCommandLineOption(
    _In_ LPCTSTR OptionName,
    _In_ BOOL IsParametric,
    _Out_writes_opt_z_(ValueSize) LPTSTR OptionValue,
    _In_ ULONG ValueSize,
    _Out_opt_ PULONG ParamLength);

BOOLEAN IsLocalSystem(VOID);
BOOLEAN IsUserInAdminGroup(VOID);
VOID RunAsLocalSystem(VOID);

BOOL IsElevated(
    _In_opt_ HANDLE ProcessHandle);

PCHAR PELoaderGetProcNameBySDTIndex(
    _In_ ULONG_PTR MappedImageBase,
    _In_ ULONG SDTIndex);
