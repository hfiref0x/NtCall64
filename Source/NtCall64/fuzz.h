/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2021
*
*  TITLE:       FUZZ.H
*
*  VERSION:     1.35
*
*  DATE:        21 Feb 2021
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#define W32SYSCALLSTART     0x1000
#define MAX_PARAMETERS		32
#define SIZEOF_FUZZDATA		13

#define FUZZ_THREAD_TIMEOUT_SEC (30)
#define FUZZ_PASS_COUNT         (64) * (1024)

static const ULONG_PTR fuzzdata[SIZEOF_FUZZDATA] = {
    0x0000000000000000, 0x000000000000ffff, 0x000000000000fffe, 0x00007ffffffeffff,
    0x00007ffffffefffe, 0x00007fffffffffff, 0x00007ffffffffffe, 0x0000800000000000,
    0x8000000000000000, 0xffff080000000000, 0xfffff80000000000, 0xffff800000000000,
    0xffff800000000001
};

VOID FuzzRun(
    _In_ NTCALL_CONTEXT *Context);

BOOL FuzzLookupWin32kNames(
    _In_ LPWSTR ModuleName,
    _Inout_ NTCALL_CONTEXT *Context);

BOOL FuzzFindW32pServiceTable(
    _In_ HMODULE MappedImageBase,
    _In_ PRAW_SERVICE_TABLE ServiceTable);

BOOL FuzzFindKiServiceTable(
    _In_ ULONG_PTR MappedImageBase,
    _In_ PRAW_SERVICE_TABLE ServiceTable);
