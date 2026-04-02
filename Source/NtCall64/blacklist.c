/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2026
*
*  TITLE:       BLACKLIST.C
*
*  VERSION:     2.01
*
*  DATE:        01 Apr 2026
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
    DWORD Hash;
    const UCHAR* p;
    UCHAR ch;

    if (Name == NULL)
        return 0;

    Hash = 2166136261UL;
    p = (const UCHAR*)Name;

    while (*p) {
        ch = *p++;
        if (ch >= 'A' && ch <= 'Z')
            ch = (UCHAR)(ch - 'A' + 'a');

        Hash ^= ch;
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

    if (Entry == NULL) {
        return 0;
    }

    Entry->Hash = Hash;
    Entry->Name = (PCHAR)(Entry + 1);
    _strncpy_a((char*)Entry->Name, Length, SyscallName, Length - 1);

    InsertHeadList(&BlackList->HashTable[BucketIndex], &Entry->ListEntry);
    BlackList->NumberOfEntries += 1;

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
    LPSTR Section, SectionPtr;
    ULONG nSize, SectionSize, BytesRead, Length;
    CHAR ConfigFilePath[MAX_PATH + 16];
    HANDLE BlackListHeap;
    ULONG i;
    BOOL bSuccess;

    Section = NULL;
    BlackListHeap = NULL;
    bSuccess = FALSE;

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

        BlackList->HeapHandle = BlackListHeap;
        for (i = 0; i < BLACKLIST_HASH_TABLE_SIZE; i++) {
            InitializeListHead(&BlackList->HashTable[i]);
        }

        nSize = 4 * (1024 * 1024);
        Section = (LPSTR)HeapAlloc(BlackListHeap, HEAP_ZERO_MEMORY, nSize);
        if (Section == NULL)
            break;

        SectionSize = GetPrivateProfileSectionA(ConfigSectionName, Section, nSize, ConfigFilePath);
        if (SectionSize == 0)
            break;

        BytesRead = 0;
        SectionPtr = Section;

        while (BytesRead < SectionSize && *SectionPtr) {
            Length = BlackListAddEntry(BlackList, SectionPtr);
            if (Length == 0) {
                BlackList->NumberOfEntries = 0;
                break;
            }
            BytesRead += Length;
            SectionPtr += Length;
        }

        if (BlackList->NumberOfEntries == 0)
            break;

        bSuccess = TRUE;

    } while (FALSE);

    if (Section) {
        HeapFree(BlackListHeap, 0, Section);
    }

    if (!bSuccess) {
        if (BlackListHeap) {
            HeapDestroy(BlackListHeap);
        }
        RtlSecureZeroMemory(BlackList, sizeof(BLACKLIST));
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
            if (_strcmpi_a(Entry->Name, SyscallName) == 0)
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
