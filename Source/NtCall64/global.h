/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2025
*
*  TITLE:       GLOBAL.H
*
*  VERSION:     2.01
*
*  DATE:        02 Dec 2025
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

#pragma warning(disable: 4005)  // Macro redefinition
#pragma warning(disable: 6258)  // Using TerminateThread does not allow proper thread clean up.
#pragma warning(disable: 6320)  // Exception-filter expression is the constant EXCEPTION_EXECUTE_HANDLER. This might mask exceptions that were not intended to be handled.

#include <windows.h>
#include <ntstatus.h>
#include <intrin.h>
#include <strsafe.h>
#include "ntos.h"
#include "minirtl\minirtl.h"
#include "minirtl\_filename.h"
#include "minirtl\cmdline.h"
#include "blacklist.h"

#pragma comment(lib, "Version.lib")

#define TEXT_COLOR_CYAN FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY
#define TEXT_COLOR_RED FOREGROUND_RED | FOREGROUND_INTENSITY
#define TEXT_COLOR_YELLOW (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY)

typedef struct _RAW_SERVICE_TABLE {
    ULONG   CountOfEntries;
    LPVOID* ServiceTable;
    PBYTE   StackArgumentTable;
} RAW_SERVICE_TABLE, * PRAW_SERVICE_TABLE;

#define MAX_SYSCALL_COUNT 0x10000
#define WIN32U_DLL TEXT("win32u.dll")

#include "sup.h"
#include "log.h"

typedef struct _CALL_PARAM {
    ULONG Syscall;
    ULONG ParametersInStack;
    ULONG ThreadTimeout;
    ULONG64 NumberOfPassesForCall;
    PVOID LogParams;
    BOOL EnableParamsHeuristic;
    LPCSTR ServiceName;
} CALL_PARAM, *PCALL_PARAM;

typedef struct _NTCALL_CONTEXT {
    BOOL LogEnabled;
    BOOL ProbeWin32k;
    BOOL ProbeSingleSyscall;
    BOOL ProbeFromSyscallId;
    BOOL EnableParamsHeuristic;
    BOOL IsUserFullAdmin;
    BOOL IsLocalSystem;
    BOOL IsElevated;
    union {
        ULONG SingleSyscallId;
        ULONG StartingSyscallId;
    } u1;
    ULONG ThreadWaitTimeout;
    ULONG64 SyscallPassCount;
    PVOID NtdllBase;
    PVOID SystemModuleBase;
    PCHAR *Win32pServiceTableNames;
    PWIN32_SHADOWTABLE Win32ShadowTable;
    RAW_SERVICE_TABLE ServiceTable;
    BLACKLIST BlackList;
    RTL_OSVERSIONINFOW OsVersion;
} NTCALL_CONTEXT, *PNTCALL_CONTEXT;

typedef struct _NTCALL_FUZZ_PARAMS {
    BOOL LogEnabled;
    BOOL LogToFile;
    BOOL ProbeWin32k;
    BOOL ProbeSingleSyscall;
    BOOL ProbeFromSyscallId;
    BOOL EnableParamsHeuristic;
    union {
        ULONG SingleSyscallId;
        ULONG StartingSyscallId;
    } u1;
    ULONG ThreadWaitTimeout;
    ULONG64 SyscallPassCount;
    WCHAR szLogDeviceOrFile[MAX_PATH + 1];
} NTCALL_FUZZ_PARAMS, *PNTCALL_FUZZ_PARAMS;

typedef enum _FUZZ_ALLOC_TYPE {
    AllocTypeVirtualAlloc,
    AllocTypeSid
} FUZZ_ALLOC_TYPE;

#define MAX_FUZZING_ALLOCATIONS 32
typedef struct _FUZZ_MEMORY_TRACKER {
    volatile LONG Lock;
    ULONG Count;
    PVOID Addresses[MAX_FUZZING_ALLOCATIONS];
    FUZZ_ALLOC_TYPE Types[MAX_FUZZING_ALLOCATIONS];
    BOOLEAN InUse;
} FUZZ_MEMORY_TRACKER, * PFUZZ_MEMORY_TRACKER;

extern NTCALL_CONTEXT g_ctx;
extern NTCALL_LOG_PARAMS g_Log;
extern __declspec(thread) FUZZ_MEMORY_TRACKER g_MemoryTracker;

#include "fuzz.h"
