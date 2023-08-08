/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2023
*
*  TITLE:       LOG.H
*
*  VERSION:     1.37
*
*  DATE:        04 Aug 2023
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

typedef struct _NTCALL_LOG_PARAMS {
    BOOL LogToFile;
    HANDLE LogHandle;
} NTCALL_LOG_PARAMS, * PNTCALL_LOG_PARAMS;

BOOLEAN FuzzOpenLog(
    _In_ LPWSTR LogDeviceFileName,
    _In_ PNTCALL_LOG_PARAMS LogParams);

VOID FuzzCloseLog(
    _In_ PNTCALL_LOG_PARAMS LogParams);

VOID FuzzLogCallName(
    _In_ PNTCALL_LOG_PARAMS LogParams,
    _In_ LPCSTR ServiceName);

VOID FuzzLogCallParameters(
    _In_ PNTCALL_LOG_PARAMS LogParams,
    _In_ ULONG ServiceId,
    _In_ ULONG NumberOfArguments,
    _In_ ULONG_PTR* Arguments);
