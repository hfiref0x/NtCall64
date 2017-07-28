/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2017
*
*  TITLE:       UTIL.H
*
*  VERSION:     1.20
*
*  DATE:        28 July 2017
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

typedef struct _BADCALLS {
    ULONG Count;
    CHAR **Syscalls;
} BADCALLS, *PBADCALLS;

void force_priv();

void log_call(
    ULONG ServiceNumber,
    ULONG ParametersInStack,
    ULONG_PTR *Parameters);

BOOL GetImageVersionInfo(
    _In_ LPWSTR lpFileName,
    _Out_opt_ ULONG *MajorVersion,
    _Out_opt_ ULONG *MinorVersion,
    _Out_opt_ ULONG *Build,
    _Out_opt_ ULONG *Revision);

BOOL ReadBlacklistCfg(
    BADCALLS *Cfg,
    LPSTR CfgFileName,
    LPSTR CfgSection);

BOOL SyscallBlacklisted(
    LPSTR Syscall,
    BADCALLS *Cfg);

VOID OutputConsoleMessage(
    _In_ LPCSTR lpMessage);
