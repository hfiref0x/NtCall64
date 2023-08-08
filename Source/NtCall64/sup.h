/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2023
*
*  TITLE:       SUP.H
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

typedef struct _WIN32_SHADOWTABLE {
    ULONG Index;
    CHAR Name[256];
    struct _WIN32_SHADOWTABLE *NextService;
} WIN32_SHADOWTABLE, *PWIN32_SHADOWTABLE;

#define supHeapAlloc(Size) RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Size)
#define supHeapFree(Memory) RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, Memory)

VOID supShowNtStatus(
    _In_ LPCSTR lpText,
    _In_ NTSTATUS Status);

VOID ConsoleInit(
    VOID);

VOID ConsoleShowMessage(
    _In_ LPCSTR lpMessage,
    _In_opt_ WORD wColor);

BOOLEAN supGetCommandLineOption(
    _In_ LPCWSTR OptionName,
    _In_ BOOLEAN IsParametric,
    _Out_writes_opt_z_(ValueSize) LPWSTR OptionValue,
    _In_ ULONG ValueSize,
    _Out_opt_ PULONG ParamLength);

NTSTATUS supIsLocalSystem(
    _In_ HANDLE hToken,
    _Out_ PBOOLEAN pbResult);

BOOLEAN supUserIsFullAdmin(
    _In_ HANDLE hToken);

VOID supRunAsLocalSystem(VOID);

BOOLEAN supIsClientElevated(
    _In_ HANDLE ProcessHandle);

PCHAR supLdrGetProcNameBySDTIndex(
    _In_ PVOID MappedImageBase,
    _In_ ULONG SDTIndex);

NTSTATUS supMapImageNoExecute(
    _In_ PUNICODE_STRING ImagePath,
    _Out_ PVOID* BaseAddress);

LPVOID supLdrGetProcAddressEx(
    _In_ LPVOID ImageBase,
    _In_ LPCSTR RoutineName);
