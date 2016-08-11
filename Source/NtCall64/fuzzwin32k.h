/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016
*
*  TITLE:       FUZZWIN32K.H
*
*  VERSION:     1.00
*
*  DATE:        11 July 2016
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

typedef struct _CALL_PARAM {
    ULONG Syscall;
    ULONG ParametersInStack;
} CALL_PARAM, *PCALL_PARAM;

void fuzz_win32k();
