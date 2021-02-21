/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2021
*
*  TITLE:       GLOBAL.H
*
*  VERSION:     1.35
*
*  DATE:        21 Feb 2021
*
*  Global definitions.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#if !defined UNICODE
#error ANSI build is not supported
#endif

#if defined (_MSC_VER)
#if (_MSC_VER >= 1900)
#ifdef _DEBUG
#pragma comment(lib, "vcruntimed.lib")
#pragma comment(lib, "ucrtd.lib")
#pragma comment(lib, "ucrt.lib")
#else
#pragma comment(lib, "libucrt.lib")
#pragma comment(lib, "libvcruntime.lib")
#endif
#endif
#endif

#pragma warning(disable: 4005)  // macro redefinition

#include <windows.h>
#include <ntstatus.h>
#include <intrin.h>
#include "ntos.h"
#include "hde\hde64.h"
#include "minirtl\minirtl.h"
#include "minirtl\_filename.h"
#include "minirtl\cmdline.h"
#include "blacklist.h"
#include "util.h"
#include "log.h"

#pragma comment(lib, "Version.lib")

typedef struct _RAW_SERVICE_TABLE {
    ULONG   CountOfEntries;
    LPVOID* ServiceTable;
    PBYTE   StackArgumentTable;
} RAW_SERVICE_TABLE, * PRAW_SERVICE_TABLE;

typedef struct _CALL_PARAM {
    ULONG Syscall;
    ULONG ParametersInStack;
    ULONG ThreadTimeout;
    ULONG64 NumberOfPassesForCall;
    PVOID LogParams;
} CALL_PARAM, *PCALL_PARAM;

typedef struct _NTCALL_CONTEXT {
    BOOL LogEnabled;
    BOOL ProbeWin32k;
    BOOL ProbeSingleSyscall;
    BOOL IsUserInAdminGroup;
    BOOL IsLocalSystem;
    BOOL IsElevated;
    ULONG SingleSyscallId;
    ULONG ThreadWaitTimeout;
    ULONG64 SyscallPassCount;
    ULONG_PTR hNtdll;
    ULONG_PTR SystemImageBase;
    CHAR **Win32pServiceTableNames;
    RAW_SERVICE_TABLE ServiceTable;
    BLACKLIST BlackList;
    WCHAR szSystemDirectory[MAX_PATH + 1];
} NTCALL_CONTEXT, *PNTCALL_CONTEXT;

typedef struct _NTCALL_FUZZ_PARAMS {
    BOOL EnableLog;
    BOOL LogToFile;
    BOOL ProbeWin32k;
    BOOL ProbeSingleSyscall;
    ULONG SingleSyscallId;
    ULONG ThreadWaitTimeout;
    ULONG64 SyscallPassCount;
    WCHAR szLogDeviceOrFile[MAX_PATH + 1];
} NTCALL_FUZZ_PARAMS, *PNTCALL_FUZZ_PARAMS;

extern NTCALL_CONTEXT g_ctx;
extern NTCALL_LOG_PARAMS g_Log;

#include "fuzz.h"
