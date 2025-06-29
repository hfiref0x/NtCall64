/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2025
*
*  TITLE:       LOG.H
*
*  VERSION:     2.00
*
*  DATE:        27 Jun 2025
*
*  Log support header file.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#define NC64_LOG_MAX_ARGS 16

typedef struct _NTCALL_LOG_PARAMS {
    BOOL LogToFile;
    HANDLE LogHandle;
} NTCALL_LOG_PARAMS, * PNTCALL_LOG_PARAMS;

#pragma pack(push, 1)
typedef struct _NC64_SYSCALL_LOG_ENTRY {
    ULONG SyscallNumber;
    ULONG ArgCount;
    ULONG_PTR Arguments[NC64_LOG_MAX_ARGS];
} NC64_SYSCALL_LOG_ENTRY, * PNC64_SYSCALL_LOG_ENTRY;
#pragma pack(pop)

BOOLEAN FuzzOpenLog(
    _In_ LPWSTR LogDeviceFileName,
    _In_ PNTCALL_LOG_PARAMS LogParams);

VOID FuzzCloseLog(
    _In_ PNTCALL_LOG_PARAMS LogParams);

VOID FuzzLogCallBinary(
    _In_ PNTCALL_LOG_PARAMS LogParams,
    _In_ ULONG ServiceId,
    _In_ ULONG NumberOfArguments,
    _In_ ULONG_PTR* Arguments);
