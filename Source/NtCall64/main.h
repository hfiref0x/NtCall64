/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2019
*
*  TITLE:       MAIN.H
*
*  VERSION:     1.33
*
*  DATE:        22 Nov 2019
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

typedef struct _RAW_SERVICE_TABLE {
    ULONG   CountOfEntries;
    LPVOID  *ServiceTable;
    PBYTE   StackArgumentTable;
} RAW_SERVICE_TABLE, *PRAW_SERVICE_TABLE;

typedef struct _CALL_PARAM {
    ULONG Syscall;
    ULONG ParametersInStack;
    ULONG ThreadTimeout;
    ULONG64 NumberOfPassesForCall;
} CALL_PARAM, *PCALL_PARAM;

#include "util.h"

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
    HANDLE LogHandle;
    ULONG_PTR hNtdll;
    ULONG_PTR SystemImageBase;
    CHAR **Win32pServiceTableNames;
    RAW_SERVICE_TABLE ServiceTable;
    BLACKLIST BlackList;
    WCHAR szSystemDirectory[MAX_PATH + 1];
} NTCALL_CONTEXT, *PNTCALL_CONTEXT;

extern NTCALL_CONTEXT g_ctx;

#include "fuzz.h"

