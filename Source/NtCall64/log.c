/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2021
*
*  TITLE:       LOG.C
*
*  VERSION:     1.35
*
*  DATE:        21 Feb 2021
*
*  Log support.
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
    HANDLE hFile;
    CHAR szWelcome[128];
    DWORD bytesIO;
    DWORD openFlags = OPEN_EXISTING;

    if (LogParams->LogToFile) openFlags = CREATE_ALWAYS; //always overwrite existing log file.

    hFile = CreateFile(LogDeviceFileName,
        GENERIC_WRITE | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        openFlags,
        FILE_FLAG_WRITE_THROUGH,
        NULL);

    if (hFile != INVALID_HANDLE_VALUE) {

        _strcpy_a(szWelcome, "\r\n[NC64] Logging start.\r\n");
        WriteFile(hFile, (LPCVOID)&szWelcome,
            (DWORD)_strlen_a(szWelcome), &bytesIO, NULL);

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
    CHAR	szBye[128];
    DWORD	bytesIO;

    HANDLE logHandle = LogParams->LogHandle;

    if (logHandle == INVALID_HANDLE_VALUE)
        return;

    _strcpy_a(szBye, "\r\n[NC64] Log stop.\r\n");
    WriteFile(logHandle,
        (LPCVOID)&szBye, (DWORD)_strlen_a(szBye), &bytesIO, NULL);

    CloseHandle(logHandle);
    LogParams->LogHandle = INVALID_HANDLE_VALUE;
}

/*
* FuzzLogCallName
*
* Purpose:
*
* Send syscall name to the log before it is not too late.
*
*/
VOID FuzzLogCallName(
    _In_ PNTCALL_LOG_PARAMS LogParams,
    _In_ LPCSTR ServiceName
)
{
    ULONG bytesIO;
    HANDLE logHandle = LogParams->LogHandle;
    CHAR szLog[128];

    if (logHandle != INVALID_HANDLE_VALUE) {
        WriteFile(logHandle, (LPCVOID)ServiceName,
            (DWORD)_strlen_a(ServiceName), &bytesIO, NULL);

        _strcpy_a(szLog, "\r\n");
        WriteFile(logHandle, (LPCVOID)&szLog,
            (DWORD)_strlen_a(szLog), &bytesIO, NULL);
    }
}

/*
* FuzzLogCallParameters
*
* Purpose:
*
* Send syscall parameters to the log before it is not too late.
*
*/
VOID FuzzLogCallParameters(
    _In_ PNTCALL_LOG_PARAMS LogParams,
    _In_ ULONG ServiceId,
    _In_ ULONG NumberOfArguments,
    _In_ ULONG_PTR* Arguments
)
{
    ULONG i;
    DWORD bytesIO;
    HANDLE logHandle = LogParams->LogHandle;
    BOOL logToFile = LogParams->LogToFile;
    CHAR szLog[2048];

    if (logHandle == INVALID_HANDLE_VALUE)
        return;

    _strcpy_a(szLog, "[NC64] ");
    ultostr_a(ServiceId, _strend_a(szLog));
    ultostr_a(NumberOfArguments, _strcat_a(szLog, "\t"));
    _strcat_a(szLog, "\t");

    for (i = 0; i < NumberOfArguments; i++) {
        u64tohex_a(Arguments[i], _strcat_a(szLog, " "));
    }
    _strcat_a(szLog, "\r\n");
    WriteFile(logHandle, (LPCVOID)&szLog,
        (DWORD)_strlen_a(szLog), &bytesIO, NULL);

    if (logToFile)
        FlushFileBuffers(logHandle);
}
