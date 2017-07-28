/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2017
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.20
*
*  DATE:        28 July 2017
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
#define PARAM_SYSCALL   "-call"
#define PARAM_HELP      "-help"

//
// Help output.
//
#define T_HELP	"NtCall64, Windows NT x64 syscall fuzzer, based on NtCall by Peter Kosyh.\n\n\r\
Optional parameters to execute: \n\n\r\
NTCALL64 -help \n\r\
NTCALL64 [-log] \n\r\
NTCALL64 -win32k [-log] \n\r\
NTCALL64 -call id [-log] \n\n\r\
  -help   - Show this help information;\n\r\
  -log    - Enable logging to file last call parameters;\n\r\
  -win32k - Fuzz win32k graphical subsystem table, otherwise fuzz ntos table;\n\r\
  -call   - Fuzz syscall by supplied numeric id (can be from any table).\n\n\r\
  Example: ntcall64.exe -win32k -log"

BOOL g_Log = FALSE;

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

    if (g_Log) {
        log_call(ServiceIndex, ParametersInStack, Arguments);
    }
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
* fuzz_callproc
*
* Purpose:
*
* Handler for fuzzing thread.
*
*/
DWORD WINAPI fuzz_callproc(
    PVOID Parameter
)
{
    ULONG  r;
    HMODULE hUser32 = 0;
    CALL_PARAM *CallParam = (PCALL_PARAM)Parameter;

    //
    //  Convert thread to GUI.
    //
    if (CallParam->Syscall >= W32SYSCALLSTART)
        hUser32 = LoadLibrary(TEXT("user32.dll"));


    for (r = 0; r < 256 * 1024; r++) {
        gofuzz(CallParam->Syscall, CallParam->ParametersInStack);
    }

    if (hUser32) FreeLibrary(hUser32);

    return 0;
}

/*
* fuzz_syscall
*
* Purpose:
*
* Launch service table fuzzing using new single thread.
*
*/
VOID fuzz_syscall(
    _In_ ULONG SyscallNumber)
{
    BOOL                IsWin32k, bFound = FALSE, bCond = FALSE;
    ULONG               i, r;
    HANDLE              hCallThread;
    ULONG_PTR           KernelImage = 0;
    CALL_PARAM          CallParam;
    WCHAR               szBuffer[MAX_PATH * 2];
    RAW_SERVICE_TABLE	ServiceTable;

    do {
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        if (!GetSystemDirectory(szBuffer, MAX_PATH))
            break;

        IsWin32k = (SyscallNumber >= W32SYSCALLSTART);

        if (IsWin32k) {
            _strcat(szBuffer, TEXT("\\win32k.sys"));
        }
        else {
            _strcat(szBuffer, TEXT("\\ntoskrnl.exe"));
        }

        KernelImage = (ULONG_PTR)LoadLibraryEx(szBuffer, NULL, 0);
        if (KernelImage == 0)
            break;

        RtlSecureZeroMemory(&ServiceTable, sizeof(ServiceTable));

        if (IsWin32k) {
            bFound = find_w32pservicetable((HMODULE)KernelImage, &ServiceTable);
        }
        else
        {
            bFound = find_kiservicetable(KernelImage, &ServiceTable);
        }

        if (!bFound)
            break;

        i = SyscallNumber;
        if (IsWin32k) {
            i -= W32SYSCALLSTART;
        }

        if (i >= ServiceTable.CountOfEntries) {
            OutputConsoleMessage("Syscall number exceeds current system available range.\r\n");
            break;
        }

        force_priv();

        CallParam.ParametersInStack = ServiceTable.StackArgumentTable[i];
        CallParam.Syscall = SyscallNumber;
        hCallThread = CreateThread(NULL, 0, fuzz_callproc, (LPVOID)&CallParam, 0, &r);
        if (hCallThread) {
            if (WaitForSingleObject(hCallThread, 20 * 1000) == WAIT_TIMEOUT) {
                OutputConsoleMessage("Timeout reached for callproc of the given service.\r\n");
                TerminateThread(hCallThread, (DWORD)-1);
            }
            CloseHandle(hCallThread);
        }

    } while (bCond);

    if (KernelImage != 0) FreeLibrary((HMODULE)KernelImage);
    OutputConsoleMessage("Single service fuzzing complete.\r\n");
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
    BOOL    bCommandFound = FALSE;
    ULONG   SyscallNumber = 0;
    LPCSTR  lpCommandLine;
    PVOID   ExceptionHandler;
    CHAR    szCmdLine[MAX_PATH + 1];

    ExceptionHandler = RtlAddVectoredExceptionHandler(1, &VehHandler);
    if (ExceptionHandler) {

        lpCommandLine = (LPCSTR)GetCommandLineA();

        RtlSecureZeroMemory(szCmdLine, sizeof(szCmdLine));
        GetCommandLineParamA(lpCommandLine, 1, (LPSTR)&szCmdLine, MAX_PATH, NULL);

        //
        // Parse first param, could be -log, -win32k, -call
        //
        // Available params combinations:
        // _empty_ (run fuzz over ntos)
        // -log (run fuzz over ntos and log to file last call params)
        //
        // -win32k (run fuzz over win32k)
        //     -log (log to file last call params)
        //
        // -call (run fuzz over given syscall id)
        //     syscall (id number)
        //       -log (log to file last call params)
        //

        if (szCmdLine[0] == 0) {
            bCommandFound = TRUE;
            fuzz_ntos();
        }
        else {

            if (_strcmpi_a(szCmdLine, PARAM_HELP) == 0) {
                bCommandFound = TRUE;
                OutputConsoleMessage(T_HELP);
            }
            else

                if (_strcmpi_a(szCmdLine, PARAM_LOG) == 0) {
                    bCommandFound = TRUE;
                    g_Log = TRUE;
                    fuzz_ntos();
                }
                else

                    if (_strcmpi_a(szCmdLine, PARAM_WIN32K) == 0) {
                        bCommandFound = TRUE;
                        RtlSecureZeroMemory(szCmdLine, sizeof(szCmdLine));
                        GetCommandLineParamA(lpCommandLine, 2, (LPSTR)&szCmdLine, MAX_PATH, NULL);
                        if (_strcmpi_a(szCmdLine, PARAM_LOG) == 0) g_Log = TRUE;
                        fuzz_win32k();
                    }
                    else

                        if (_strcmpi_a(szCmdLine, PARAM_SYSCALL) == 0) {
                            bCommandFound = TRUE;

                            RtlSecureZeroMemory(szCmdLine, sizeof(szCmdLine));
                            GetCommandLineParamA(lpCommandLine, 2, (LPSTR)&szCmdLine, MAX_PATH, NULL);
                            SyscallNumber = (ULONG)strtoul_a(szCmdLine);

                            RtlSecureZeroMemory(szCmdLine, sizeof(szCmdLine));
                            GetCommandLineParamA(lpCommandLine, 3, (LPSTR)&szCmdLine, MAX_PATH, NULL);
                            if (_strcmpi_a(szCmdLine, PARAM_LOG) == 0) g_Log = TRUE;

                            fuzz_syscall(SyscallNumber);
                        }
        }

        if (bCommandFound == FALSE) {
            OutputConsoleMessage("Invalid parameter or combination.\r\n");
        }
        RtlRemoveVectoredExceptionHandler(ExceptionHandler);
    }
    ExitProcess(0);
}
