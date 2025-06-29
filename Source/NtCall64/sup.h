/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2025
*
*  TITLE:       SUP.H
*
*  VERSION:     2.00
*
*  DATE:        27 Jun 2025
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

typedef struct _WIN32_SHADOWTABLE {
    ULONG Index;
    CHAR Name[MAX_PATH];
    struct _WIN32_SHADOWTABLE *NextService;
} WIN32_SHADOWTABLE, *PWIN32_SHADOWTABLE;

#define supHeapAlloc(Size) RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Size)
#define supHeapFree(Memory) RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, Memory)

VOID supShowNtStatus(
    _In_ LPCSTR lpText,
    _In_ NTSTATUS Status);

BOOL ConsoleInit(
    VOID);

VOID ConsoleShowMessage(
    _In_ LPCSTR lpMessage,
    _In_ WORD wColor);

VOID ConsoleShowMessage2(
    _In_ LPCSTR lpMessage,
    _In_ WORD wColor);

_Success_(return)
BOOL supGetParamOption(
    _In_ LPCWSTR params,
    _In_ LPCWSTR optionName,
    _In_ BOOL isParametric,
    _Out_opt_ LPWSTR value,
    _In_ ULONG valueLength, //in chars
    _Out_opt_ PULONG paramLength);

NTSTATUS supIsLocalSystem(
    _In_ HANDLE hToken,
    _Out_ PBOOL pbResult);

BOOLEAN supUserIsFullAdmin(
    _In_ HANDLE hToken);

VOID supRunAsLocalSystem(VOID);

BOOLEAN supIsClientElevated(
    _In_ HANDLE ProcessHandle);

PCHAR supGetProcNameBySDTIndex(
    _In_ PVOID MappedImageBase,
    _In_ ULONG SDTIndex);

ULONG supEnumWin32uServices(
    _In_ HANDLE HeapHandle,
    _In_ LPVOID ModuleBase,
    _Inout_ PWIN32_SHADOWTABLE* Table);

NTSTATUS supMapImageNoExecute(
    _In_ PUNICODE_STRING ImagePath,
    _Out_ PVOID* BaseAddress);

LPVOID supGetProcAddressEx(
    _In_ LPVOID ImageBase,
    _In_ LPCSTR RoutineName);

BOOLEAN supFindKiServiceTable(
    _In_ PVOID MappedImageBase,
    _In_ PRAW_SERVICE_TABLE ServiceTable);

BOOLEAN supFindW32pServiceTable(
    _In_ PVOID MappedImageBase,
    _In_ PRAW_SERVICE_TABLE ServiceTable);

PCHAR supResolveW32kServiceNameById(
    _In_ ULONG ServiceId,
    _In_opt_ PWIN32_SHADOWTABLE ShadowTable);

BOOL supIsComPort(
    _In_ LPCWSTR wsz);
