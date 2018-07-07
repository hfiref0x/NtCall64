/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2018
*
*  TITLE:       MAIN.H
*
*  VERSION:     1.21
*
*  DATE:        04 July 2018
*
*  Global definitions.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

#if !defined UNICODE
#error ANSI build is not supported
#endif

#if (_MSC_VER >= 1900) 
#ifdef _DEBUG
#pragma comment(lib, "vcruntimed.lib")
#pragma comment(lib, "ucrtd.lib")
#else
#pragma comment(lib, "libvcruntime.lib")
#endif
#endif

#pragma warning(disable: 28278) // Function name appears with no prototype in scope
#pragma warning(disable: 4005)  // macro redefinition
#pragma warning(disable: 4054)  // from function pointer to data pointer
#pragma warning(disable: 4055)  // from data pointer to function pointer
#pragma warning(disable: 4091)  // 'typedef ': ignored on left of '' when no variable is declared
#pragma warning(disable: 4152)  // nonstandard extension, function/data pointer conversion in expression
#pragma warning(disable: 4201)  // nonstandard extension used : nameless struct/union
#pragma warning(disable: 6102)  // Using %s from failed function call at line %u
#pragma warning(disable: 6320)  // exception-filter expression is the constant EXCEPTION_EXECUTE_HANDLER

#include <windows.h>
#include <ntstatus.h>
#include "minirtl\minirtl.h"
#include "minirtl\_filename.h"
#include "minirtl\cmdline.h"
#include "ntos.h"
#include "hde\hde64.h"
#include "util.h"
#include "fuzz.h"

#define CFG_FILE       "badcalls.ini"

void gofuzz(
    ULONG ServiceIndex, 
    ULONG ParametersInStack
    );
