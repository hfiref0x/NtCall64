/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2017
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.10
*
*  DATE:        18 July 2017
*
*  Program entry point.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "main.h"
#include "fuzzntos.h"
#include "fuzzwin32k.h"

#define PARAM_LOG       "-log"
#define PARAM_WIN32K    "-win32k"

#ifdef _DEBUG
BOOL g_Log = FALSE;
#endif

NTSTATUS ntSyscallGate(ULONG ServiceId, ULONG ArgumentCount, ULONG_PTR *Arguments);

/*
* gofuzz
*
* Purpose:
*
* Fuzzing procedure, building parameters list and using syscall gate.
*
*/
void gofuzz(ULONG ServiceIndex, ULONG ParametersInStack)
{
    ULONG_PTR	Arguments[MAX_PARAMETERS];
    ULONG		c, r, k;

    RtlSecureZeroMemory(Arguments, sizeof(Arguments));

    ParametersInStack /= 4;

    for (c = 0; c < ParametersInStack + 4; c++)
    {
        k = ~GetTickCount();
        r = RtlRandomEx(&k);
        Arguments[c] = fuzzdata[r % SIZEOF_FUZZDATA];
    }

#ifdef _DEBUG
    if (g_Log) {
        log_call(ServiceIndex, ParametersInStack, Arguments);
    }
#endif
    ntSyscallGate(ServiceIndex, ParametersInStack + 4, Arguments);
}

/*
* VehHandler
*
* Purpose:
*
* Vectored exception handler.
*
*/
LONG CALLBACK VehHandler(
    EXCEPTION_POINTERS *ExceptionInfo
)
{
    PVOID pExitThread;

    pExitThread = GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "ExitThread");
    ExceptionInfo->ContextRecord->Rip = (DWORD64)pExitThread;

    return EXCEPTION_CONTINUE_EXECUTION;
}

/*
* main
*
* Purpose:
*
* Program main, process command line options.
*
*/
void main()
{
    PVOID   ExceptionHandler;
    CHAR    szCmdLine[MAX_PATH + 1];

    ExceptionHandler = RtlAddVectoredExceptionHandler(1, &VehHandler);
    if (ExceptionHandler) {

        RtlSecureZeroMemory(szCmdLine, sizeof(szCmdLine));
        GetCommandLineParamA((LPCSTR)GetCommandLineA(), 1, (LPSTR)&szCmdLine, MAX_PATH, NULL);

        if (_strcmpi_a(szCmdLine, PARAM_WIN32K) == 0) {
            RtlSecureZeroMemory(szCmdLine, sizeof(szCmdLine));
            GetCommandLineParamA((LPCSTR)GetCommandLineA(), 2, (LPSTR)&szCmdLine, MAX_PATH, NULL);
#ifdef _DEBUG
            if (_strcmpi_a(szCmdLine, PARAM_LOG) == 0)
                g_Log = TRUE;
#endif
            fuzz_win32k();
        }
        else {

#ifdef _DEBUG
            if (_strcmpi_a(szCmdLine, PARAM_LOG) == 0)
                g_Log = TRUE;
#endif
            fuzz_ntos();
        }
        RtlRemoveVectoredExceptionHandler(ExceptionHandler);
    }
    ExitProcess(0);
}
