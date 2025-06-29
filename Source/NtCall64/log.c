/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2025
*
*  TITLE:       LOG.C
*
*  VERSION:     2.00
*
*  DATE:        27 Jun 2025
*
*  Log support (binary form).
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

/*
* FuzzOpenLog
*
* Purpose:
*
* Open port/file for logging.
*
*/
BOOLEAN FuzzOpenLog(
    _In_ LPWSTR LogDeviceFileName,
    _In_ PNTCALL_LOG_PARAMS LogParams
)
{
    DWORD openFlags = OPEN_EXISTING;
    HANDLE hFile;

    if (LogParams == NULL)
        return FALSE;

    if (LogParams->LogToFile)
        openFlags = CREATE_ALWAYS;

    hFile = CreateFile(LogDeviceFileName,
        GENERIC_WRITE | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        openFlags,
        FILE_FLAG_WRITE_THROUGH,
        NULL);

    if (hFile != INVALID_HANDLE_VALUE) {
        LogParams->LogHandle = hFile;
        return TRUE;
    }
    return FALSE;
}

/*
* FuzzCloseLog
*
* Purpose:
*
* Close log file or port handle.
*
*/
VOID FuzzCloseLog(
    _In_ PNTCALL_LOG_PARAMS LogParams
)
{
    HANDLE logHandle;

    if (LogParams == NULL)
        return;

    logHandle = LogParams->LogHandle;
    if (logHandle == INVALID_HANDLE_VALUE)
        return;

    CloseHandle(logHandle);
    LogParams->LogHandle = INVALID_HANDLE_VALUE;
    LogParams->LogToFile = FALSE;
}

/*
* FuzzLogCallBinary
*
* Purpose:
*
* Send syscall parameters to the log before it is not too late.
*
*/
VOID FuzzLogCallBinary(
    _In_ PNTCALL_LOG_PARAMS LogParams,
    _In_ ULONG ServiceId,
    _In_ ULONG NumberOfArguments,
    _In_ ULONG_PTR* Arguments
)
{
    NC64_SYSCALL_LOG_ENTRY entry;
    DWORD toWrite, bytesIO;
    HANDLE logHandle;

    if (LogParams == NULL || Arguments == NULL)
        return;

    logHandle = LogParams->LogHandle;
    if (logHandle == INVALID_HANDLE_VALUE)
        return;

    if (NumberOfArguments > NC64_LOG_MAX_ARGS)
        NumberOfArguments = NC64_LOG_MAX_ARGS;

    entry.SyscallNumber = ServiceId;
    entry.ArgCount = NumberOfArguments;
    RtlZeroMemory(entry.Arguments, sizeof(entry.Arguments));
    if (NumberOfArguments)
        memcpy(entry.Arguments, Arguments, NumberOfArguments * sizeof(ULONG_PTR));

    toWrite = sizeof(ULONG) * 2 + sizeof(ULONG_PTR) * NC64_LOG_MAX_ARGS;
    WriteFile(logHandle, &entry, toWrite, &bytesIO, NULL);

    if (LogParams->LogToFile)
        FlushFileBuffers(logHandle);
}
