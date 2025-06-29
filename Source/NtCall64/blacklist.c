/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2025
*
*  TITLE:       BLACKLIST.C
*
*  VERSION:     2.00
*
*  DATE:        27 Jun 2025
*
*  Syscall blacklist handling.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

#define BLACKLIST_HASH_TABLE_SIZE 256
#define BLACKLIST_HASH_MASK (BLACKLIST_HASH_TABLE_SIZE - 1)

/*
* BlackListHashString
*
* Purpose:
*
* Hash string using FNV-1a algorithm.
*
*/
DWORD BlackListHashString(
    _In_ LPCSTR Name
)
{
    DWORD Hash = 2166136261UL;
    PCHAR p = (PCHAR)Name;

    while (*p) {
        Hash ^= *p++;
        Hash *= 16777619;
    }

    return Hash;
}

/*
* BlackListAddEntry
*
* Purpose:
*
* Add new entry to the blacklist hash table.
*
*/
ULONG BlackListAddEntry(
    _In_ BLACKLIST* BlackList,
    _In_ LPCSTR SyscallName
)
{
    PBL_ENTRY Entry;
    ULONG Length, BucketIndex;
    DWORD Hash;

    Length = (ULONG)_strlen_a(SyscallName) + 1;
    Hash = BlackListHashString(SyscallName);
    BucketIndex = Hash & BLACKLIST_HASH_MASK;

    Entry = (PBL_ENTRY)HeapAlloc(
        BlackList->HeapHandle,
        HEAP_ZERO_MEMORY,
        sizeof(BL_ENTRY) + Length
    );

    if (Entry) {
        Entry->Hash = Hash;

        Entry->Name = (PCHAR)(Entry + 1);
        _strncpy_a((char*)Entry->Name, Length, SyscallName, Length - 1);

        InsertHeadList(&BlackList->HashTable[BucketIndex], &Entry->ListEntry);
        BlackList->NumberOfEntries += 1;
    }

    return Length;
}

/*
* BlackListCreateFromFile
*
* Purpose:
*
* Read blacklist from ini file to allocated memory.
*
*/
BOOL BlackListCreateFromFile(
    _In_ BLACKLIST* BlackList,
    _In_ LPCSTR ConfigFileName,
    _In_ LPCSTR ConfigSectionName
)
{
    LPSTR Section = NULL, SectionPtr;
    ULONG nSize, SectionSize, BytesRead, Length;
    CHAR ConfigFilePath[MAX_PATH + 16];
    HANDLE BlackListHeap = NULL;
    ULONG i;

    do {
        RtlSecureZeroMemory(BlackList, sizeof(BLACKLIST));
        RtlSecureZeroMemory(ConfigFilePath, sizeof(ConfigFilePath));
        if (GetModuleFileNameA(NULL, (LPSTR)&ConfigFilePath, MAX_PATH) == 0)
            break;

        _filepath_a(ConfigFilePath, ConfigFilePath);
        _strcat_a(ConfigFilePath, ConfigFileName);

        BlackListHeap = HeapCreate(HEAP_GROWABLE, 0, 0);
        if (BlackListHeap == NULL)
            break;

        HeapSetInformation(BlackListHeap, HeapEnableTerminationOnCorruption, NULL, 0);

        nSize = 2 * (1024 * 1024);
        Section = (LPSTR)HeapAlloc(BlackListHeap, HEAP_ZERO_MEMORY, nSize);
        if (Section == NULL)
            break;

        SectionSize = GetPrivateProfileSectionA(ConfigSectionName, Section, nSize, ConfigFilePath);
        if (SectionSize == 0)
            break;

        BlackList->HeapHandle = BlackListHeap;

        for (i = 0; i < BLACKLIST_HASH_TABLE_SIZE; i++) {
            InitializeListHead(&BlackList->HashTable[i]);
        }

        BytesRead = 0;
        SectionPtr = Section;

        while (BytesRead < SectionSize && *SectionPtr) {
            Length = BlackListAddEntry(BlackList, SectionPtr);
            BytesRead += Length;
            SectionPtr += Length;
        }

    } while (FALSE);

    if (Section) {
        HeapFree(BlackListHeap, 0, Section);
    }

    if (BlackList->NumberOfEntries == 0) {
        if (BlackListHeap) {
            HeapDestroy(BlackListHeap);
            BlackList->HeapHandle = NULL;
        }
        return FALSE;
    }

    return TRUE;
}

/*
* BlackListEntryPresent
*
* Purpose:
*
* Return TRUE if syscall is in blacklist.
*
*/
BOOL BlackListEntryPresent(
    _In_ BLACKLIST* BlackList,
    _In_ LPCSTR SyscallName
)
{
    DWORD Hash;
    ULONG BucketIndex;
    PLIST_ENTRY Head, Next;
    BL_ENTRY* Entry;

    if (!BlackList || !BlackList->NumberOfEntries)
        return FALSE;

    Hash = BlackListHashString(SyscallName);
    BucketIndex = Hash & BLACKLIST_HASH_MASK;

    // Check only the specific bucket that should contain the entry
    Head = &BlackList->HashTable[BucketIndex];
    Next = Head->Flink;

    while ((Next != NULL) && (Next != Head)) {
        Entry = CONTAINING_RECORD(Next, BL_ENTRY, ListEntry);

        if (Entry->Hash == Hash) {
            if (_strcmp_a(Entry->Name, SyscallName) == 0)
                return TRUE;
        }

        Next = Next->Flink;
    }

    return FALSE;
}

/*
* BlackListDestroy
*
* Purpose:
*
* Destroy blacklist heap and zero blacklist structure.
*
*/
VOID BlackListDestroy(
    _In_ BLACKLIST* BlackList
)
{
    if (BlackList) {
        if (BlackList->HeapHandle) HeapDestroy(BlackList->HeapHandle);
        RtlSecureZeroMemory(BlackList, sizeof(BLACKLIST));
    }
}
