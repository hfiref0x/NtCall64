/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2026
*
*  TITLE:       TESTS.C
*
*  VERSION:     2.10
*
*  DATE:        09 Sep 2026
*
*  NTCALL64 internal tests.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

BOOL GateCompareProcessBasicInformation(
    _In_ PPROCESS_BASIC_INFORMATION DirectInfo,
    _In_ ULONG DirectLength,
    _In_ PPROCESS_BASIC_INFORMATION GateInfo,
    _In_ ULONG GateLength
)
{
    if (DirectLength != GateLength)
        return FALSE;

    if (DirectInfo->PebBaseAddress != GateInfo->PebBaseAddress)
        return FALSE;

    if (DirectInfo->UniqueProcessId != GateInfo->UniqueProcessId)
        return FALSE;

    if (DirectInfo->InheritedFromUniqueProcessId != GateInfo->InheritedFromUniqueProcessId)
        return FALSE;

    return TRUE;
}

BOOL GateCompareThreadBasicInformation(
    _In_ PTHREAD_BASIC_INFORMATION DirectInfo,
    _In_ ULONG DirectLength,
    _In_ PTHREAD_BASIC_INFORMATION GateInfo,
    _In_ ULONG GateLength
)
{
    if (DirectLength != GateLength)
        return FALSE;

    if (DirectInfo->TebBaseAddress != GateInfo->TebBaseAddress)
        return FALSE;

    if (DirectInfo->ClientId.UniqueProcess != GateInfo->ClientId.UniqueProcess)
        return FALSE;

    if (DirectInfo->ClientId.UniqueThread != GateInfo->ClientId.UniqueThread)
        return FALSE;

    return TRUE;
}

BOOL GateCompareObjectBasicInformation(
    _In_ POBJECT_BASIC_INFORMATION DirectInfo,
    _In_ ULONG DirectLength,
    _In_ POBJECT_BASIC_INFORMATION GateInfo,
    _In_ ULONG GateLength
)
{
    if (DirectLength != GateLength)
        return FALSE;

    if (DirectInfo->Attributes != GateInfo->Attributes)
        return FALSE;

    if (DirectInfo->GrantedAccess != GateInfo->GrantedAccess)
        return FALSE;

    if (DirectInfo->HandleCount != GateInfo->HandleCount)
        return FALSE;

    return TRUE;
}

BOOL GateIsAcceptableYieldStatus(
    _In_ NTSTATUS Status
)
{
    return (Status == STATUS_SUCCESS || Status == STATUS_NO_YIELD_PERFORMED);
}

BOOL RunRealSyscallGateSmokeTests(
    VOID
)
{
    BOOL bResult;
    NTSTATUS statusDirect, statusGate;
    ULONG syscallId;
    ULONG_PTR args[MAX_PARAMETERS];
    CHAR szText[256];

    PROCESS_BASIC_INFORMATION pbiDirect;
    PROCESS_BASIC_INFORMATION pbiGate;
    ULONG pbiLenDirect, pbiLenGate;

    THREAD_BASIC_INFORMATION tbiDirect;
    THREAD_BASIC_INFORMATION tbiGate;
    ULONG tbiLenDirect, tbiLenGate;

    OBJECT_BASIC_INFORMATION obiDirect;
    OBJECT_BASIC_INFORMATION obiGate;
    ULONG obiLenDirect, obiLenGate;

    bResult = TRUE;

    syscallId = supGetSyscallNumberFromNtdll("NtYieldExecution");
    if (syscallId == ULONG_MAX) {
        ConsoleShowMessage("[!] NtYieldExecution syscall number lookup failed", TEXT_COLOR_RED);
        bResult = FALSE;
    }
    else {
        RtlSecureZeroMemory(args, sizeof(args));

        statusDirect = NtYieldExecution();
        statusGate = ntSyscallGate(syscallId, 0, args);

        if (!GateIsAcceptableYieldStatus(statusDirect) ||
            !GateIsAcceptableYieldStatus(statusGate))
        {
            StringCchPrintfA(szText, RTL_NUMBER_OF(szText),
                "[!] NtYieldExecution mismatch, direct=0x%lX gate=0x%lX",
                statusDirect, statusGate);
            ConsoleShowMessage(szText, TEXT_COLOR_RED);
            bResult = FALSE;
        }
        else {
            ConsoleShowMessage("[+] NtYieldExecution gate smoke test passed", TEXT_COLOR_CYAN);
        }
    }

    syscallId = supGetSyscallNumberFromNtdll("NtClose");
    if (syscallId == ULONG_MAX) {
        ConsoleShowMessage("[!] NtClose syscall number lookup failed", TEXT_COLOR_RED);
        bResult = FALSE;
    }
    else {
        RtlSecureZeroMemory(args, sizeof(args));
        args[0] = (ULONG_PTR)INVALID_HANDLE_VALUE;

        statusDirect = NtClose(INVALID_HANDLE_VALUE);
        statusGate = ntSyscallGate(syscallId, 1, args);

        if (statusDirect != statusGate) {
            StringCchPrintfA(szText, RTL_NUMBER_OF(szText),
                "[!] NtClose mismatch, direct=0x%lX gate=0x%lX",
                statusDirect, statusGate);
            ConsoleShowMessage(szText, TEXT_COLOR_RED);
            bResult = FALSE;
        }
        else {
            ConsoleShowMessage("[+] NtClose gate smoke test passed", TEXT_COLOR_CYAN);
        }
    }

    syscallId = supGetSyscallNumberFromNtdll("NtQueryInformationProcess");
    if (syscallId == ULONG_MAX) {
        ConsoleShowMessage("[!] NtQueryInformationProcess syscall number lookup failed", TEXT_COLOR_RED);
        bResult = FALSE;
    }
    else {
        RtlSecureZeroMemory(&pbiDirect, sizeof(pbiDirect));
        RtlSecureZeroMemory(&pbiGate, sizeof(pbiGate));
        pbiLenDirect = 0;
        pbiLenGate = 0;

        statusDirect = NtQueryInformationProcess(
            NtCurrentProcess(),
            ProcessBasicInformation,
            &pbiDirect,
            sizeof(pbiDirect),
            &pbiLenDirect);

        RtlSecureZeroMemory(args, sizeof(args));
        args[0] = (ULONG_PTR)NtCurrentProcess();
        args[1] = (ULONG_PTR)ProcessBasicInformation;
        args[2] = (ULONG_PTR)&pbiGate;
        args[3] = (ULONG_PTR)sizeof(pbiGate);
        args[4] = (ULONG_PTR)&pbiLenGate;

        statusGate = ntSyscallGate(syscallId, 5, args);

        if (statusDirect != statusGate) {
            StringCchPrintfA(szText, RTL_NUMBER_OF(szText),
                "[!] NtQueryInformationProcess status mismatch, direct=0x%lX gate=0x%lX",
                statusDirect, statusGate);
            ConsoleShowMessage(szText, TEXT_COLOR_RED);
            bResult = FALSE;
        }
        else if (!GateCompareProcessBasicInformation(&pbiDirect, pbiLenDirect, &pbiGate, pbiLenGate)) {
            ConsoleShowMessage("[!] NtQueryInformationProcess data mismatch", TEXT_COLOR_RED);
            bResult = FALSE;
        }
        else {
            ConsoleShowMessage("[+] NtQueryInformationProcess gate smoke test passed", TEXT_COLOR_CYAN);
        }
    }

    syscallId = supGetSyscallNumberFromNtdll("NtQueryInformationThread");
    if (syscallId == ULONG_MAX) {
        ConsoleShowMessage("[!] NtQueryInformationThread syscall number lookup failed", TEXT_COLOR_RED);
        bResult = FALSE;
    }
    else {
        RtlSecureZeroMemory(&tbiDirect, sizeof(tbiDirect));
        RtlSecureZeroMemory(&tbiGate, sizeof(tbiGate));
        tbiLenDirect = 0;
        tbiLenGate = 0;

        statusDirect = NtQueryInformationThread(
            NtCurrentThread(),
            ThreadBasicInformation,
            &tbiDirect,
            sizeof(tbiDirect),
            &tbiLenDirect);

        RtlSecureZeroMemory(args, sizeof(args));
        args[0] = (ULONG_PTR)NtCurrentThread();
        args[1] = (ULONG_PTR)ThreadBasicInformation;
        args[2] = (ULONG_PTR)&tbiGate;
        args[3] = (ULONG_PTR)sizeof(tbiGate);
        args[4] = (ULONG_PTR)&tbiLenGate;

        statusGate = ntSyscallGate(syscallId, 5, args);

        if (statusDirect != statusGate) {
            StringCchPrintfA(szText, RTL_NUMBER_OF(szText),
                "[!] NtQueryInformationThread status mismatch, direct=0x%lX gate=0x%lX",
                statusDirect, statusGate);
            ConsoleShowMessage(szText, TEXT_COLOR_RED);
            bResult = FALSE;
        }
        else if (!GateCompareThreadBasicInformation(&tbiDirect, tbiLenDirect, &tbiGate, tbiLenGate)) {
            ConsoleShowMessage("[!] NtQueryInformationThread data mismatch", TEXT_COLOR_RED);
            bResult = FALSE;
        }
        else {
            ConsoleShowMessage("[+] NtQueryInformationThread gate smoke test passed", TEXT_COLOR_CYAN);
        }
    }

    syscallId = supGetSyscallNumberFromNtdll("NtQueryObject");
    if (syscallId == ULONG_MAX) {
        ConsoleShowMessage("[!] NtQueryObject syscall number lookup failed", TEXT_COLOR_RED);
        bResult = FALSE;
    }
    else {
        RtlSecureZeroMemory(&obiDirect, sizeof(obiDirect));
        RtlSecureZeroMemory(&obiGate, sizeof(obiGate));
        obiLenDirect = 0;
        obiLenGate = 0;

        statusDirect = NtQueryObject(
            NtCurrentProcess(),
            ObjectBasicInformation,
            &obiDirect,
            sizeof(obiDirect),
            &obiLenDirect);

        RtlSecureZeroMemory(args, sizeof(args));
        args[0] = (ULONG_PTR)NtCurrentProcess();
        args[1] = (ULONG_PTR)ObjectBasicInformation;
        args[2] = (ULONG_PTR)&obiGate;
        args[3] = (ULONG_PTR)sizeof(obiGate);
        args[4] = (ULONG_PTR)&obiLenGate;

        statusGate = ntSyscallGate(syscallId, 5, args);

        if (statusDirect != statusGate) {
            StringCchPrintfA(szText, RTL_NUMBER_OF(szText),
                "[!] NtQueryObject status mismatch, direct=0x%lX gate=0x%lX",
                statusDirect, statusGate);
            ConsoleShowMessage(szText, TEXT_COLOR_RED);
            bResult = FALSE;
        }
        else if (!GateCompareObjectBasicInformation(&obiDirect, obiLenDirect, &obiGate, obiLenGate)) {
            ConsoleShowMessage("[!] NtQueryObject data mismatch", TEXT_COLOR_RED);
            bResult = FALSE;
        }
        else {
            ConsoleShowMessage("[+] NtQueryObject gate smoke test passed", TEXT_COLOR_CYAN);
        }
    }

    return bResult;
}

BOOL RunSyscallGateTests(
    VOID
)
{
    BOOL bResult = TRUE;
    ULONG i;

    for (i = 0; i < 100; i++) {
        if (!RunRealSyscallGateSmokeTests()) {
            ConsoleShowMessage("[!] Syscall gate repeated tests failed", TEXT_COLOR_RED);
            bResult = FALSE;
            break;
        }
    }
    if (i == 100) {
        ConsoleShowMessage("[+] Syscall gate repeated tests passed", TEXT_COLOR_CYAN);
    }

    return bResult;
}
