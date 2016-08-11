/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016
*
*  TITLE:       UTIL.H
*
*  VERSION:     1.00
*
*  DATE:        11 July 2016
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
    ULONG_PTR *Parameters
);

BOOL GetWin32kBuildVersion(
    LPWSTR szImagePath,
    ULONG *BuildNumber
);

BOOL ReadBlacklistCfg(
    BADCALLS *Cfg,
    LPSTR CfgFileName,
    LPSTR CfgSection
);

BOOL SyscallBlacklisted(
    LPSTR Syscall,
    BADCALLS *Cfg
);
