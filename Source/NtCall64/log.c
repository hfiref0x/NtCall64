/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2026
*
*  TITLE:       LOG.C
*
*  VERSION:     2.10
*
*  DATE:        09 Sep 2026
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
    WCHAR szDeviceName[MAX_PATH + 1];

    if (LogParams == NULL || LogDeviceFileName == NULL)
        return FALSE;

    LogParams->FailureReported = FALSE;

    if (LogParams->LogToFile)
        openFlags = CREATE_ALWAYS;

    if (!LogParams->LogToFile && supIsComPort(LogDeviceFileName)) {

        if (((LogDeviceFileName[3] >= L'0') && (LogDeviceFileName[3] <= L'9')) &&
            (LogDeviceFileName[4] != 0))
        {
            StringCchPrintfW(szDeviceName, RTL_NUMBER_OF(szDeviceName), L"\\\\.\\%ws", LogDeviceFileName);
        }
        else {
            _strcpy(szDeviceName, LogDeviceFileName);
        }

        LogDeviceFileName = szDeviceName;
    }

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
    LogParams->FailureReported = FALSE;
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
    BOOL bResult;
    DWORD toWrite, bytesIO;
    ULONG storedArgCount;
    ULONG flags;
    HANDLE logHandle;
    NC64_SYSCALL_LOG_ENTRY entry;

    if (LogParams == NULL || Arguments == NULL)
        return;

    logHandle = LogParams->LogHandle;
    if (logHandle == INVALID_HANDLE_VALUE)
        return;

    storedArgCount = NumberOfArguments;
    if (storedArgCount > NC64_LOG_MAX_ARGS)
        storedArgCount = NC64_LOG_MAX_ARGS;

    flags = 0;
    if (ServiceId >= W32SYSCALLSTART)
        flags |= NC64_LOG_FLAG_WIN32K;
    if (g_ctx.EnableParamsHeuristic)
        flags |= NC64_LOG_FLAG_HEURISTIC;

    RtlSecureZeroMemory(&entry, sizeof(entry));
    entry.Signature = NC64_LOG_SIGNATURE;
    entry.Version = NC64_LOG_VERSION;
    entry.Flags = flags;
    entry.SyscallNumber = ServiceId;
    entry.ArgCount = NumberOfArguments;
    entry.StoredArgCount = storedArgCount;

    if (storedArgCount)
        RtlCopyMemory(entry.Arguments, Arguments, storedArgCount * sizeof(ULONG_PTR));

    toWrite = sizeof(entry);
    bytesIO = 0;

    bResult = WriteFile(logHandle, &entry, toWrite, &bytesIO, NULL);
    if (!bResult || bytesIO != toWrite) {

        if (!LogParams->FailureReported) {
            LogParams->FailureReported = TRUE;
            ConsoleShowMessage("[!] Logging write failed, logging disabled", TEXT_COLOR_RED);
        }

        CloseHandle(logHandle);
        LogParams->LogHandle = INVALID_HANDLE_VALUE;
        LogParams->LogToFile = FALSE;
        return;
    }

    if (LogParams->LogToFile) {
        if (!FlushFileBuffers(logHandle)) {
            if (!LogParams->FailureReported) {
                LogParams->FailureReported = TRUE;
                ConsoleShowMessage("[!] Log flush failed, logging disabled", TEXT_COLOR_RED);
            }

            CloseHandle(logHandle);
            LogParams->LogHandle = INVALID_HANDLE_VALUE;
            LogParams->LogToFile = FALSE;
        }
    }
}
