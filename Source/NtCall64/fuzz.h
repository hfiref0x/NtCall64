/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2025
*
*  TITLE:       FUZZ.H
*
*  VERSION:     2.00
*
*  DATE:        27 Jun 2025
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#define W32SYSCALLSTART          0x1000
#define MAX_PARAMETERS           32
#define MAX_STRUCT_BUFFER_SIZE   4096
#define MAX_KEYVALUE_BUFFER_SIZE 1024
#ifdef _DEBUG
#define FUZZ_THREAD_TIMEOUT_SEC (30)
#else
#define FUZZ_THREAD_TIMEOUT_SEC (30)
#endif
#define FUZZ_PASS_COUNT         (64) * (1024)

#define FUZZ_PARAMS_STACK_DIVISOR 4
#define FUZZ_EXTRA_PARAMS         4
#define FUZZ_TIMEOUT_MULTIPLE     8

// Define Windows parameter types
typedef enum _PARAM_TYPE_HINT {
    ParamTypeGeneral = 0,    // No specific type known
    ParamTypeHandle,         // NT handle
    ParamTypeAddress,        // Memory address/pointer
    ParamTypeStatus,         // Status block
    ParamTypeFlag,           // Flags or options
    ParamTypeAccess,         // Access mask
    ParamTypeUnicodeStr,     // UNICODE_STRING structure
    ParamTypeObjectAttr,     // OBJECT_ATTRIBUTES structure
    ParamTypeWinHandle,      // Window handle
    ParamTypeGdiHandle,      // GDI object handle
    ParamTypeToken,          // Token handle
    ParamTypePrivilege,      // TOKEN_PRIVILEGES structure 
    ParamTypeInfoClass,      // Information class value
    ParamTypeBufferSize,     // Buffer size for I/O operations
    ParamTypeTimeout,        // Timeout value
    ParamTypeRetLength,      // Return length pointer
    ParamTypeSecDesc,        // Security descriptor
    ParamTypeClientId,       // CLIENT_ID structure
    ParamTypeKeyValue,       // Registry key value info
    ParamTypeOutPtr          // Output pointer receiving a value
} PARAM_TYPE_HINT;

// Structure for known syscall parameter types
typedef struct _SYSCALL_PARAM_INFO {
    LPCSTR Name;                        // Name of the syscall
    PARAM_TYPE_HINT ParamTypes[16];     // Type hints for up to 16 parameters
} SYSCALL_PARAM_INFO, * PSYSCALL_PARAM_INFO;

typedef struct _FUZZ_STATS {
    ULONG TotalCalls;
    ULONG TimeoutCalls;
    ULONG SuccessCalls;
    ULONG ErrorCalls;
    ULONG CrashedCalls;
} FUZZ_STATS, * PFUZZ_STATS;

VOID FuzzRun(
    _In_ NTCALL_CONTEXT *Context);

BOOLEAN FuzzLookupWin32kNames(
    _Inout_ NTCALL_CONTEXT *Context);

VOID FuzzDetectParameterTypes(
    _In_ LPCSTR ServiceName,
    _In_ ULONG ParameterCount,
    _In_ BOOL IsWin32kSyscall,
    _Out_writes_(ParameterCount) PARAM_TYPE_HINT* TypeHints);

ULONG_PTR FuzzGenerateParameter(
    _In_ ULONG ParameterIndex,
    _In_ PARAM_TYPE_HINT TypeHint,
    _In_ BOOL IsWin32kSyscall,
    _In_ BOOL EnableParamsHeuristic,
    _In_ PBYTE FuzzStructBuffer);

PARAM_TYPE_HINT FuzzDetermineParameterTypeHeuristic(
    _In_ LPCSTR SyscallName,
    _In_ ULONG ParameterIndex,
    _In_ BOOL IsWin32kSyscall);

VOID FuzzTrackAllocation(
    _In_ PVOID Address,
    _In_ FUZZ_ALLOC_TYPE Type);

VOID FuzzCleanupAllocations();

#ifdef _DEBUG
BOOL VerifySyscallDatabaseSorted(UINT DbType);
#endif

PSECURITY_DESCRIPTOR CreateFuzzedSecurityDescriptor(_In_ BYTE* FuzzStructBuffer);
PUNICODE_STRING CreateFuzzedUnicodeString(_In_ BYTE* FuzzStructBuffer);
POBJECT_ATTRIBUTES CreateFuzzedObjectAttributes(_In_ BYTE* FuzzStructBuffer);
PTOKEN_PRIVILEGES CreateFuzzedTokenPrivileges(_In_ BYTE* FuzzStructBuffer);
PIO_STATUS_BLOCK CreateFuzzedIoStatusBlock(_In_ BYTE* FuzzStructBuffer);
PKERNEL_USER_TIMES CreateFuzzedProcessTimes(_In_ BYTE* FuzzStructBufferID);
PLARGE_INTEGER CreateFuzzedLargeInteger(_In_ BYTE* FuzzStructBuffer);
PCLIENT_ID CreateFuzzedClientId(_In_ BYTE* FuzzStructBuffer);
PSECTION_IMAGE_INFORMATION CreateFuzzedSectionImageInfo(_In_ BYTE* FuzzStructBuffer);
PVOID CreateFuzzedKeyValueParameter(VOID);
