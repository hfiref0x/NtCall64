/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2017
*
*  TITLE:       FUZZ.H
*
*  VERSION:     1.20
*
*  DATE:        28 July 2017
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#define W32SYSCALLSTART     0x1000
#define MAX_PARAMETERS		17
#define SIZEOF_FUZZDATA		13

static const ULONG_PTR fuzzdata[SIZEOF_FUZZDATA] = {
    0x0000000000000000, 0x000000000000ffff, 0x000000000000fffe, 0x00007ffffffeffff,
    0x00007ffffffefffe, 0x00007fffffffffff, 0x00007ffffffffffe, 0x0000800000000000,
    0x8000000000000000, 0xffff080000000000, 0xfffff80000000000, 0xffff800000000000,
    0xffff800000000001
};

typedef struct _RAW_SERVICE_TABLE {
    ULONG	 CountOfEntries;
    LPVOID	*ServiceTable;
    PBYTE	 StackArgumentTable;
} RAW_SERVICE_TABLE, *PRAW_SERVICE_TABLE;

typedef struct _CALL_PARAM {
    ULONG Syscall;
    ULONG ParametersInStack;
} CALL_PARAM, *PCALL_PARAM;
