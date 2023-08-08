/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2023
*
*  TITLE:       FUZZ.H
*
*  VERSION:     1.37
*
*  DATE:        04 Aug 2023
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#define W32SYSCALLSTART     0x1000
#define MAX_PARAMETERS      32

#define FUZZ_THREAD_TIMEOUT_SEC (30)
#define FUZZ_PASS_COUNT         (64) * (1024)

VOID FuzzRun(
    _In_ NTCALL_CONTEXT *Context);

BOOLEAN FuzzLookupWin32kNames(
    _Inout_ NTCALL_CONTEXT *Context);

BOOLEAN FuzzFindW32pServiceTable(
    _In_ PVOID MappedImageBase,
    _In_ PRAW_SERVICE_TABLE ServiceTable);

BOOLEAN FuzzFindKiServiceTable(
    _In_ PVOID MappedImageBase,
    _In_ PRAW_SERVICE_TABLE ServiceTable);
