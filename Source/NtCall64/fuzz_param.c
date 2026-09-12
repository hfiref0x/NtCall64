/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2025 - 2026
*
*  TITLE:       FUZZ_PARAM.C
*
*  VERSION:     2.10
*
*  DATE:        11 Sep 2026
*
*  Parameter type detection and structure generation for syscall fuzzing.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "fuzz_data.h"

__declspec(thread) FUZZ_MEMORY_TRACKER g_MemoryTracker;
__declspec(thread) BYTE g_FuzzStructBuffer[FUZZ_PARAM_BUFFER_SIZE];

ULONG FuzzRandom(
    VOID
)
{
    ULONG x;

    x = g_MemoryTracker.Seed;
    if (x == 0) {
        x = (ULONG)__rdtsc();
        x ^= GetCurrentThreadId();
        x ^= GetCurrentProcessId();
        if (x == 0)
            x = 0xA5A5A5A5;
    }

    x ^= (x << 13);
    x ^= (x >> 17);
    x ^= (x << 5);

    g_MemoryTracker.Seed = x;
    return x;
}

#ifdef _DEBUG
BOOL VerifySyscallDatabaseSorted(UINT DbType)
{
    ULONG i;
    SYSCALL_PARAM_INFO* Database;

    Database = (DbType == 0) ? (SYSCALL_PARAM_INFO*)KnownNtSyscalls : (SYSCALL_PARAM_INFO*)KnownWin32kSyscalls;

    for (i = 1; Database[i].Name != NULL; i++) {
        if (_strcmpi_a(Database[i - 1].Name, Database[i].Name) > 0) {
            OutputDebugStringA(Database[i - 1].Name);
            OutputDebugStringA("\n");
            return FALSE;
        }
    }

    return TRUE;
}

BOOL VerifySyscallDatabaseIntegrity(UINT DbType)
{
    ULONG i;
    SYSCALL_PARAM_INFO* Database;

    Database = (DbType == 0) ? (SYSCALL_PARAM_INFO*)KnownNtSyscalls : (SYSCALL_PARAM_INFO*)KnownWin32kSyscalls;

    for (i = 0; Database[i].Name != NULL; i++) {

        if (Database[i].Name[0] == 0) {
            OutputDebugStringA("Empty syscall name found in database\n");
            return FALSE;
        }

        if (i > 0) {
            if (_strcmpi_a(Database[i - 1].Name, Database[i].Name) == 0) {
                OutputDebugStringA("Duplicate syscall entry found in database\n");
                OutputDebugStringA(Database[i].Name);
                OutputDebugStringA("\n");
                return FALSE;
            }
        }
    }

    return TRUE;
}
#endif

LPCSTR FuzzSkipSyscallPrefix(
    _In_ LPCSTR SyscallName
)
{
    if (SyscallName == NULL)
        return NULL;

    if (_strncmp_a(SyscallName, "NtUser", 6) == 0)
        return SyscallName + 6;

    if (_strncmp_a(SyscallName, "NtGdi", 5) == 0)
        return SyscallName + 5;

    if (_strncmp_a(SyscallName, "Nt", 2) == 0)
        return SyscallName + 2;

    if (_strncmp_a(SyscallName, "Zw", 2) == 0)
        return SyscallName + 2;

    return SyscallName;
}

BOOL FuzzHasVerbPrefix(
    _In_ LPCSTR SyscallName,
    _In_ LPCSTR Verb
)
{
    LPCSTR namePart;

    namePart = FuzzSkipSyscallPrefix(SyscallName);
    if (namePart == NULL || Verb == NULL)
        return FALSE;

    return (_strncmp_a(namePart, Verb, _strlen_a(Verb)) == 0);
}

BOOL FuzzHasTerm(
    _In_ LPCSTR SyscallName,
    _In_ LPCSTR Term
)
{
    if (SyscallName == NULL || Term == NULL)
        return FALSE;

    return (_strstr_a(SyscallName, Term) != NULL);
}

PBYTE FuzzGetParameterStructSlot(
    _In_ PBYTE BufferBase,
    _In_ ULONG ParameterIndex
)
{
    if (BufferBase == NULL || ParameterIndex >= MAX_PARAMETERS)
        return NULL;

    return BufferBase + (ParameterIndex * FUZZ_PARAM_SLOT_SIZE);
}

SIZE_T FuzzGetRemainingSlotSize(
    _In_ ULONG ParameterIndex
)
{
    UNREFERENCED_PARAMETER(ParameterIndex);
    return FUZZ_PARAM_SLOT_SIZE;
}

/*
* FuzzTrackAllocation
*
* Purpose:
*
* Track allocated memory so it can be freed even if the stack is corrupted.
*
*/
BOOLEAN FuzzTrackAllocation(
    _In_ PVOID Address,
    _In_ FUZZ_ALLOC_TYPE Type
)
{
    if (Address == NULL)
        return FALSE;

    while (InterlockedCompareExchange(&g_MemoryTracker.Lock, 1, 0) != 0) {
        YieldProcessor();
    }

    if (g_MemoryTracker.Count < MAX_FUZZING_ALLOCATIONS) {
        g_MemoryTracker.Addresses[g_MemoryTracker.Count] = Address;
        g_MemoryTracker.Types[g_MemoryTracker.Count] = Type;
        g_MemoryTracker.Count++;
        InterlockedExchange(&g_MemoryTracker.Lock, 0);
        return TRUE;
    }

    g_MemoryTracker.Overflow = TRUE;
    InterlockedExchange(&g_MemoryTracker.Lock, 0);
    return FALSE;
}
/*
* FuzzCleanupAllocations
*
* Purpose:
*
* Free all tracked memory allocations.
*
*/
VOID FuzzCleanupAllocations()
{
    ULONG i;

    while (InterlockedCompareExchange(&g_MemoryTracker.Lock, 1, 0) != 0) {
        YieldProcessor();
    }

    if (!g_MemoryTracker.InUse) {
        InterlockedExchange(&g_MemoryTracker.Lock, 0);
        return;
    }

    for (i = 0; i < g_MemoryTracker.Count; i++) {
        if (g_MemoryTracker.Addresses[i] != NULL) {
            switch (g_MemoryTracker.Types[i]) {
            case AllocTypeVirtualAlloc:
                VirtualFree(g_MemoryTracker.Addresses[i], 0, MEM_RELEASE);
                break;
            case AllocTypeSid:
                FreeSid(g_MemoryTracker.Addresses[i]);
                break;
            }
            g_MemoryTracker.Addresses[i] = NULL;
        }
    }
    g_MemoryTracker.Count = 0;
    g_MemoryTracker.InUse = FALSE;
    g_MemoryTracker.Overflow = FALSE;
    InterlockedExchange(&g_MemoryTracker.Lock, 0);
}

/*
* FuzzSyscallBinarySearch
*
* Purpose:
*
* Performs binary search on a sorted syscall database to find parameter type information.
*
*/
SYSCALL_LOOKUP_RESULT FuzzSyscallBinarySearch(
    _In_ LPCSTR SyscallName,
    _In_ ULONG ParamIndex,
    _In_ const SYSCALL_PARAM_INFO* Database,
    _In_ ULONG DatabaseCount,
    _Out_ PARAM_TYPE_HINT* TypeHint
)
{
    INT left, right, mid, result;

    if (TypeHint == NULL)
        return SyscallLookupNotFound;

    *TypeHint = ParamTypeGeneral;

    left = 0;
    right = (INT)DatabaseCount - 1;

    while (left <= right) {
        mid = left + ((right - left) / 2);
        result = _strcmpi_a(SyscallName, Database[mid].Name);

        if (result == 0) {
            if (ParamIndex < RTL_NUMBER_OF(Database[mid].ParamTypes)) {
                *TypeHint = Database[mid].ParamTypes[ParamIndex];
            }
            return SyscallLookupFound;
        }

        if (result < 0) {
            right = mid - 1;
        }
        else {
            left = mid + 1;
        }
    }

    return SyscallLookupNotFound;
}

/*
* FuzzGetSyscallParamType
*
* Purpose:
*
* Lookup parameter type for a syscall in the known syscalls database.
*
*/
PARAM_TYPE_HINT FuzzGetSyscallParamType(
    _In_ LPCSTR SyscallName,
    _In_ ULONG ParamIndex,
    _In_ BOOL IsWin32kSyscall
)
{
    const SYSCALL_PARAM_INFO* pDatabase;
    ULONG databaseCount;
    PARAM_TYPE_HINT result;
    SYSCALL_LOOKUP_RESULT lookupResult;

    if (!SyscallName || ParamIndex >= 16)
        return ParamTypeGeneral;

    if (IsWin32kSyscall) {
        pDatabase = KnownWin32kSyscalls;
        databaseCount = KNOWN_WIN32K_SYSCALLS_COUNT;
    }
    else {
        pDatabase = KnownNtSyscalls;
        databaseCount = KNOWN_NT_SYSCALLS_COUNT;
    }

    lookupResult = FuzzSyscallBinarySearch(SyscallName, ParamIndex, pDatabase, databaseCount, &result);
    if (lookupResult == SyscallLookupFound) {
        return result;
    }

    return FuzzDetermineParameterTypeHeuristic(SyscallName, ParamIndex, IsWin32kSyscall);
}

/*
* FuzzDetermineParameterTypeHeuristic
*
* Purpose:
*
* Heuristic to determine parameter type based on syscall name and parameter position
* when the syscall is not found in the predefined database.
*
*/
PARAM_TYPE_HINT FuzzDetermineParameterTypeHeuristic(
    _In_ LPCSTR SyscallName,
    _In_ ULONG ParameterIndex,
    _In_ BOOL IsWin32kSyscall
)
{
    if (SyscallName == NULL)
        return ParamTypeGeneral;

    BOOL hasCreatePrefix = FuzzHasVerbPrefix(SyscallName, "Create");
    BOOL hasOpenPrefix = FuzzHasVerbPrefix(SyscallName, "Open");
    BOOL hasQueryPrefix = FuzzHasVerbPrefix(SyscallName, "Query");
    BOOL hasSetPrefix = FuzzHasVerbPrefix(SyscallName, "Set");
    BOOL hasEnumeratePrefix = FuzzHasVerbPrefix(SyscallName, "Enumerate");
    BOOL hasAllocPrefix = FuzzHasVerbPrefix(SyscallName, "Allocate");
    BOOL hasFreePrefix = FuzzHasVerbPrefix(SyscallName, "Free");
    BOOL hasGetPrefix = FuzzHasVerbPrefix(SyscallName, "Get");
    BOOL hasReadPrefix = FuzzHasVerbPrefix(SyscallName, "Read");
    BOOL hasWritePrefix = FuzzHasVerbPrefix(SyscallName, "Write");
    BOOL hasMapPrefix = FuzzHasVerbPrefix(SyscallName, "Map");
    BOOL hasUnmapPrefix = FuzzHasVerbPrefix(SyscallName, "Unmap");
    BOOL hasProtectPrefix = FuzzHasVerbPrefix(SyscallName, "Protect");
    BOOL hasLockPrefix = FuzzHasVerbPrefix(SyscallName, "Lock");
    BOOL hasUnlockPrefix = FuzzHasVerbPrefix(SyscallName, "Unlock");

    BOOL hasFileTerm = FuzzHasTerm(SyscallName, "File");
    BOOL hasKeyTerm = FuzzHasTerm(SyscallName, "Key");
    BOOL hasRegistryTerm = hasKeyTerm || FuzzHasTerm(SyscallName, "Registry");
    BOOL hasMemoryTerm = FuzzHasTerm(SyscallName, "Memory") || FuzzHasTerm(SyscallName, "Virtual");
    BOOL hasVirtualTerm = FuzzHasTerm(SyscallName, "Virtual");
    BOOL hasProcessTerm = FuzzHasTerm(SyscallName, "Process");
    BOOL hasThreadTerm = FuzzHasTerm(SyscallName, "Thread");
    BOOL hasTokenTerm = FuzzHasTerm(SyscallName, "Token");
    BOOL hasInfoTerm = FuzzHasTerm(SyscallName, "Information");
    BOOL hasReadTerm = FuzzHasTerm(SyscallName, "Read");
    BOOL hasWriteTerm = FuzzHasTerm(SyscallName, "Write");
    BOOL hasSecurityTerm = FuzzHasTerm(SyscallName, "Security") ||
        FuzzHasTerm(SyscallName, "Sacl") ||
        FuzzHasTerm(SyscallName, "Dacl");
    BOOL hasTimeTerm = FuzzHasTerm(SyscallName, "Time") ||
        FuzzHasTerm(SyscallName, "Timer") ||
        FuzzHasTerm(SyscallName, "Delay") ||
        FuzzHasTerm(SyscallName, "Wait");
    BOOL hasSectionTerm = FuzzHasTerm(SyscallName, "Section");
    BOOL hasValueTerm = FuzzHasTerm(SyscallName, "Value");
    BOOL hasClientTerm = FuzzHasTerm(SyscallName, "Client") || FuzzHasTerm(SyscallName, "PID");
    BOOL hasPrivilegeTerm = FuzzHasTerm(SyscallName, "Privilege");
    BOOL hasObjectTerm = FuzzHasTerm(SyscallName, "Object");
    BOOL hasSystemTerm = FuzzHasTerm(SyscallName, "System");
    BOOL hasPortTerm = FuzzHasTerm(SyscallName, "Port");
    BOOL hasTimerTerm = FuzzHasTerm(SyscallName, "Timer");
    BOOL hasMutantTerm = FuzzHasTerm(SyscallName, "Mutant");
    BOOL hasEventTerm = FuzzHasTerm(SyscallName, "Event");
    BOOL hasSemaphoreTerm = FuzzHasTerm(SyscallName, "Semaphore");

    BOOL isUserFunction = IsWin32kSyscall && (_strncmp_a(SyscallName, "NtUser", 6) == 0);
    BOOL isGdiFunction = IsWin32kSyscall && (_strncmp_a(SyscallName, "NtGdi", 5) == 0);
    BOOL hasWindowTerm = FuzzHasTerm(SyscallName, "Window");
    BOOL hasMenuTerm = FuzzHasTerm(SyscallName, "Menu");
    BOOL hasDCTerm = FuzzHasTerm(SyscallName, "DC");
    BOOL hasDrawTerm = FuzzHasTerm(SyscallName, "Draw") ||
        FuzzHasTerm(SyscallName, "Paint") ||
        FuzzHasTerm(SyscallName, "Fill") ||
        FuzzHasTerm(SyscallName, "Blt");
    BOOL hasNameTerm = FuzzHasTerm(SyscallName, "Name");
    BOOL hasTextTerm = FuzzHasTerm(SyscallName, "Text");
    BOOL hasColorTerm = FuzzHasTerm(SyscallName, "Color");
    BOOL hasSelectTerm = FuzzHasTerm(SyscallName, "Select");
    BOOL hasCursorTerm = FuzzHasTerm(SyscallName, "Cursor");
    BOOL hasRectTerm = FuzzHasTerm(SyscallName, "Rect") || FuzzHasTerm(SyscallName, "Rgn");
    BOOL hasPointTerm = FuzzHasTerm(SyscallName, "Point") || FuzzHasTerm(SyscallName, "Pos");
    BOOL hasInputTerm = FuzzHasTerm(SyscallName, "Input");

    BOOL isFirstParam = (ParameterIndex == 0);
    BOOL isSecondParam = (ParameterIndex == 1);
    BOOL isThirdParam = (ParameterIndex == 2);
    BOOL isFourthParam = (ParameterIndex == 3);
    BOOL isFifthParam = (ParameterIndex == 4);
    BOOL isSixthParam = (ParameterIndex == 5);
    BOOL isSeventhParam = (ParameterIndex == 6);
    BOOL isEighthParam = (ParameterIndex == 7);
    BOOL isHighIndexParam = (ParameterIndex >= 5);

    // ============================================================
    // SYSTEM-WIDE PATTERNS
    // ============================================================

    if (hasSecurityTerm) {
        if (isThirdParam || isFourthParam) {
            return ParamTypeSecDesc;
        }
    }

    if (hasTimeTerm) {
        if (isSecondParam || isThirdParam) {
            return ParamTypeTimeout;
        }
    }

    if ((hasProcessTerm || hasThreadTerm) && hasClientTerm) {
        if (isThirdParam || isFourthParam) {
            return ParamTypeClientId;
        }
    }

    if (hasPrivilegeTerm && hasTokenTerm) {
        if (isFirstParam)
            return ParamTypeToken;

        if (isThirdParam)
            return ParamTypePrivilege;
    }

    // ============================================================
    // WIN32K HEURISTICS
    // ============================================================

    if (IsWin32kSyscall) {

        if (isUserFunction) {

            if (hasGetPrefix || hasQueryPrefix) {
                if (isFirstParam) {
                    if (hasWindowTerm || hasMenuTerm)
                        return ParamTypeWinHandle;
                    return ParamTypeHandle;
                }

                if (isSecondParam) {
                    if (hasRectTerm || hasPointTerm || hasCursorTerm || hasInputTerm)
                        return ParamTypeAddress;
                    if (hasInfoTerm)
                        return ParamTypeInfoClass;
                    return ParamTypeOutPtr;
                }

                if (isThirdParam) {
                    if (hasRectTerm || hasPointTerm)
                        return ParamTypeAddress;
                    return ParamTypeFlag;
                }

                if (isFourthParam)
                    return ParamTypeOutPtr;
            }

            if (hasCreatePrefix || hasOpenPrefix) {
                if (isFirstParam) {
                    if (hasWindowTerm || hasMenuTerm)
                        return ParamTypeWinHandle;
                    return ParamTypeAddress;
                }

                if (isSecondParam) {
                    if (hasNameTerm || hasTextTerm)
                        return ParamTypeUnicodeStr;
                    return ParamTypeFlag;
                }

                if (isThirdParam) {
                    if (hasNameTerm || hasTextTerm)
                        return ParamTypeUnicodeStr;
                    return ParamTypeFlag;
                }
            }

            if (isFirstParam) {
                if (hasWindowTerm || hasMenuTerm || hasCursorTerm)
                    return ParamTypeWinHandle;
                if (hasRectTerm || hasPointTerm || hasInputTerm)
                    return ParamTypeAddress;
                return ParamTypeWinHandle;
            }

            if (isSecondParam) {
                if (hasRectTerm || hasPointTerm || hasInputTerm)
                    return ParamTypeAddress;
                if (hasNameTerm || hasTextTerm)
                    return ParamTypeUnicodeStr;
                return ParamTypeFlag;
            }

            if (isThirdParam) {
                if (hasRectTerm || hasPointTerm)
                    return ParamTypeAddress;
                if (hasGetPrefix || hasQueryPrefix)
                    return ParamTypeOutPtr;
                return ParamTypeFlag;
            }

            if (isFourthParam && (hasGetPrefix || hasQueryPrefix)) {
                return ParamTypeOutPtr;
            }
        }

        if (isGdiFunction) {

            if (isFirstParam) {
                if (hasDCTerm || hasDrawTerm || hasSelectTerm)
                    return ParamTypeGdiHandle;
                if (hasRectTerm || hasPointTerm)
                    return ParamTypeAddress;
                if (hasCreatePrefix)
                    return ParamTypeFlag;
                return ParamTypeGdiHandle;
            }

            if (isSecondParam) {
                if (hasRectTerm || hasPointTerm)
                    return ParamTypeAddress;
                if (hasSelectTerm || hasGetPrefix)
                    return ParamTypeGdiHandle;
                if (hasColorTerm)
                    return ParamTypeFlag;
                return ParamTypeFlag;
            }

            if (isThirdParam) {
                if (hasRectTerm || hasPointTerm)
                    return ParamTypeAddress;
                if (hasDrawTerm)
                    return ParamTypeFlag;
                return ParamTypeFlag;
            }

            if (isFourthParam) {
                if (hasRectTerm || hasPointTerm)
                    return ParamTypeAddress;
                return ParamTypeFlag;
            }
        }

        if (isHighIndexParam) {
            return (ParameterIndex % 2 == 0) ? ParamTypeAddress : ParamTypeFlag;
        }
    }
    else {
        // ========================================================
        // NT FAMILY / DOMAIN HEURISTICS
        // ========================================================

        // Virtual memory and related families
        if (hasVirtualTerm || hasMemoryTerm || hasAllocPrefix || hasFreePrefix ||
            hasMapPrefix || hasUnmapPrefix || hasProtectPrefix || hasLockPrefix || hasUnlockPrefix)
        {
            if (hasAllocPrefix || hasFreePrefix) {
                if (isFirstParam)
                    return ParamTypeHandle;
                if (isSecondParam || isThirdParam)
                    return ParamTypeAddress;
                if (isFourthParam)
                    return ParamTypeFlag;
                if (isFifthParam)
                    return ParamTypeFlag;
            }

            if (hasQueryPrefix && (hasVirtualTerm || hasMemoryTerm)) {
                if (isFirstParam)
                    return ParamTypeHandle;
                if (isSecondParam)
                    return ParamTypeAddress;
                if (isThirdParam)
                    return ParamTypeInfoClass;
                if (isFourthParam)
                    return ParamTypeAddress;
                if (isFifthParam)
                    return ParamTypeBufferSize;
                if (isSixthParam)
                    return ParamTypeRetLength;
            }

            if (hasReadPrefix || hasWritePrefix) {
                if (isFirstParam)
                    return ParamTypeHandle;
                if (isSecondParam)
                    return ParamTypeAddress;
                if (isThirdParam)
                    return ParamTypeAddress;
                if (isFourthParam)
                    return ParamTypeBufferSize;
                if (isFifthParam)
                    return ParamTypeRetLength;
            }

            if (hasMapPrefix || hasUnmapPrefix || hasProtectPrefix || hasLockPrefix || hasUnlockPrefix) {
                if (isFirstParam)
                    return ParamTypeHandle;
                if (isSecondParam || isThirdParam)
                    return ParamTypeAddress;
                if (isFourthParam)
                    return ParamTypeFlag;
            }
        }

        // Query/Set System Information family
        if (hasSystemTerm && hasInfoTerm) {
            if (hasQueryPrefix || hasSetPrefix) {
                if (isFirstParam)
                    return ParamTypeInfoClass;
                if (isSecondParam)
                    return ParamTypeAddress;
                if (isThirdParam)
                    return ParamTypeBufferSize;
                if (isFourthParam && hasQueryPrefix)
                    return ParamTypeRetLength;
            }
        }

        // Query/Set Information family for common object domains
        if (hasInfoTerm && (hasQueryPrefix || hasSetPrefix)) {
            if (hasProcessTerm || hasThreadTerm || hasTokenTerm || hasObjectTerm ||
                hasSectionTerm || hasFileTerm || hasKeyTerm || hasPortTerm ||
                hasEventTerm || hasMutantTerm || hasSemaphoreTerm || hasTimerTerm)
            {
                if (isFirstParam) {
                    if (hasTokenTerm)
                        return ParamTypeToken;
                    return ParamTypeHandle;
                }

                if (isSecondParam)
                    return ParamTypeInfoClass;

                if (isThirdParam)
                    return ParamTypeAddress;

                if (isFourthParam)
                    return ParamTypeBufferSize;

                if (isFifthParam && hasQueryPrefix)
                    return ParamTypeRetLength;
            }
        }

        // Open process/thread style families
        if (hasOpenPrefix && (hasProcessTerm || hasThreadTerm)) {
            if (isFirstParam)
                return ParamTypeAddress;
            if (isSecondParam)
                return ParamTypeAccess;
            if (isThirdParam)
                return ParamTypeObjectAttr;
            if (isFourthParam)
                return ParamTypeClientId;
        }

        // Open token from process/thread style families
        if (hasOpenPrefix && hasTokenTerm && (hasProcessTerm || hasThreadTerm)) {
            if (isFirstParam)
                return ParamTypeHandle;
            if (isSecondParam)
                return ParamTypeAccess;
            if (isThirdParam)
                return ParamTypeAddress;
            if (isFourthParam)
                return ParamTypeFlag;
            if (isFifthParam)
                return ParamTypeAddress;
        }

        // Section families
        if (hasSectionTerm) {
            if (hasQueryPrefix || hasSetPrefix) {
                if (isFirstParam)
                    return ParamTypeHandle;
                if (isSecondParam)
                    return ParamTypeInfoClass;
                if (isThirdParam)
                    return ParamTypeAddress;
                if (isFourthParam)
                    return ParamTypeBufferSize;
                if (isFifthParam && hasQueryPrefix)
                    return ParamTypeRetLength;
            }

            if (hasCreatePrefix || hasOpenPrefix) {
                if (isFirstParam)
                    return ParamTypeAddress;
                if (isSecondParam)
                    return ParamTypeAccess;
                if (isThirdParam)
                    return ParamTypeObjectAttr;
            }
        }

        // File I/O families
        if (hasFileTerm || hasReadTerm || hasWriteTerm) {
            if (hasReadPrefix || hasWritePrefix ||
                FuzzHasTerm(SyscallName, "FsControl") ||
                FuzzHasTerm(SyscallName, "DeviceIoControl"))
            {
                if (isFirstParam)
                    return ParamTypeHandle;
                if (isSecondParam)
                    return ParamTypeHandle;
                if (isThirdParam)
                    return ParamTypeAddress;
                if (isFourthParam)
                    return ParamTypeAddress;
                if (isFifthParam)
                    return ParamTypeStatus;
                if (isSixthParam)
                    return ParamTypeAddress;
                if (isSeventhParam)
                    return ParamTypeBufferSize;
                if (isEighthParam)
                    return ParamTypeAddress;
            }

            if (hasCreatePrefix || hasOpenPrefix) {
                if (isFirstParam)
                    return ParamTypeAddress;
                if (isSecondParam)
                    return ParamTypeAccess;
                if (isThirdParam)
                    return ParamTypeObjectAttr;
                if (isFourthParam)
                    return ParamTypeStatus;
            }

            if (hasQueryPrefix || hasSetPrefix) {
                if (isFirstParam)
                    return ParamTypeHandle;
                if (isSecondParam && !hasInfoTerm)
                    return ParamTypeStatus;
                if (isThirdParam)
                    return ParamTypeAddress;
                if (isFourthParam)
                    return ParamTypeBufferSize;
                if (isFifthParam && hasInfoTerm)
                    return ParamTypeInfoClass;
            }
        }

        // Registry / key / value families
        if (hasRegistryTerm || hasKeyTerm || hasValueTerm) {
            if (hasCreatePrefix || hasOpenPrefix) {
                if (isFirstParam)
                    return ParamTypeAddress;
                if (isSecondParam)
                    return ParamTypeAccess;
                if (isThirdParam)
                    return ParamTypeObjectAttr;
                if (isFourthParam && hasKeyTerm)
                    return ParamTypeFlag;
                if (isFifthParam && hasValueTerm)
                    return ParamTypeUnicodeStr;
            }

            if (hasQueryPrefix) {
                if (isFirstParam)
                    return ParamTypeHandle;
                if (isSecondParam) {
                    if (hasValueTerm)
                        return ParamTypeUnicodeStr;
                    return ParamTypeInfoClass;
                }
                if (isThirdParam) {
                    if (hasValueTerm)
                        return ParamTypeFlag;
                    return ParamTypeAddress;
                }
                if (isFourthParam)
                    return ParamTypeAddress;
                if (isFifthParam)
                    return ParamTypeBufferSize;
                if (isSixthParam)
                    return ParamTypeRetLength;
            }

            if (hasSetPrefix) {
                if (isFirstParam)
                    return ParamTypeHandle;
                if (isSecondParam)
                    return ParamTypeUnicodeStr;
                if (isThirdParam)
                    return ParamTypeFlag;
                if (isFourthParam)
                    return ParamTypeFlag;
                if (isFifthParam)
                    return ParamTypeAddress;
                if (isSixthParam)
                    return ParamTypeBufferSize;
            }

            if (hasEnumeratePrefix) {
                if (isFirstParam)
                    return ParamTypeHandle;
                if (isSecondParam || isThirdParam)
                    return ParamTypeFlag;
                if (isFourthParam)
                    return ParamTypeAddress;
                if (isFifthParam)
                    return ParamTypeBufferSize;
                if (isSixthParam)
                    return ParamTypeRetLength;
            }
        }

        // Generic create/open family
        if (hasCreatePrefix || hasOpenPrefix) {
            if (isFirstParam)
                return ParamTypeAddress;
            if (isSecondParam)
                return ParamTypeAccess;
            if (isThirdParam)
                return ParamTypeObjectAttr;
        }

        // Generic query/get family
        if (hasQueryPrefix || hasGetPrefix) {
            if (isFirstParam) {
                if (hasSystemTerm && hasInfoTerm)
                    return ParamTypeInfoClass;
                if (hasTokenTerm)
                    return ParamTypeToken;
                return ParamTypeHandle;
            }

            if (isSecondParam && hasInfoTerm)
                return ParamTypeInfoClass;

            if (isThirdParam)
                return ParamTypeAddress;

            if (isFourthParam)
                return ParamTypeBufferSize;

            if (isFifthParam && hasInfoTerm)
                return ParamTypeRetLength;
        }

        // Generic set family
        if (hasSetPrefix) {
            if (isFirstParam) {
                if (hasTokenTerm)
                    return ParamTypeToken;
                return ParamTypeHandle;
            }

            if (isSecondParam && hasInfoTerm)
                return ParamTypeInfoClass;

            if (isThirdParam)
                return ParamTypeAddress;

            if (isFourthParam)
                return ParamTypeBufferSize;
        }
    }

    // ============================================================
    // Defaults
    // ============================================================

    switch (ParameterIndex) {
    case 0:
        if (IsWin32kSyscall) {
            return isUserFunction ? ParamTypeWinHandle : ParamTypeGdiHandle;
        }

        if (hasSystemTerm && hasInfoTerm && (hasQueryPrefix || hasSetPrefix))
            return ParamTypeInfoClass;

        if (hasCreatePrefix || hasOpenPrefix)
            return ParamTypeAddress;

        if (hasTokenTerm)
            return ParamTypeToken;

        return ParamTypeHandle;

    case 1:
        if (!IsWin32kSyscall && (hasCreatePrefix || hasOpenPrefix))
            return ParamTypeAccess;

        if (!IsWin32kSyscall && hasInfoTerm && (hasQueryPrefix || hasSetPrefix))
            return ParamTypeInfoClass;

        return ParamTypeFlag;

    case 2:
        return ParamTypeAddress;

    case 3:
        if (!IsWin32kSyscall && (hasQueryPrefix || hasGetPrefix))
            return ParamTypeBufferSize;
        return ParamTypeFlag;

    case 4:
        if (!IsWin32kSyscall && hasInfoTerm && (hasQueryPrefix || hasGetPrefix))
            return ParamTypeRetLength;
        return ParamTypeFlag;

    default:
        return (ParameterIndex % 2) ? ParamTypeFlag : ParamTypeAddress;
    }
}

NTSTATUS NTAPI FuzzSafeThreadStart(
    _In_opt_ PVOID Parameter
)
{
    UNREFERENCED_PARAMETER(Parameter);
    return STATUS_SUCCESS;
}

BOOL FuzzBuildNtCreateThreadExArguments(
    _Out_writes_(11) ULONG_PTR* Arguments,
    _In_ PBYTE FuzzStructBuffer
)
{
    ULONG mutateIndex;
    SIZE_T stackSize;
    SIZE_T maximumStackSize;
    HANDLE* pThreadHandle;
    OBJECT_ATTRIBUTES* pObjectAttributes;
    ULONG_PTR createFlags;

    if (Arguments == NULL || FuzzStructBuffer == NULL)
        return FALSE;

    RtlSecureZeroMemory(Arguments, sizeof(ULONG_PTR) * 11);

    pThreadHandle = (HANDLE*)FuzzGetParameterStructSlot(FuzzStructBuffer, 0);
    if (pThreadHandle == NULL)
        return FALSE;
    *pThreadHandle = NULL;

    pObjectAttributes = (OBJECT_ATTRIBUTES*)FuzzGetParameterStructSlot(FuzzStructBuffer, 2);
    if (pObjectAttributes)
        RtlSecureZeroMemory(pObjectAttributes, sizeof(OBJECT_ATTRIBUTES));

    createFlags = 0x00000001ui64;
    stackSize = 0;
    maximumStackSize = 0;

    Arguments[0] = (ULONG_PTR)pThreadHandle;
    Arguments[1] = (ULONG_PTR)THREAD_ALL_ACCESS;
    Arguments[2] = 0;
    Arguments[3] = (ULONG_PTR)NtCurrentProcess();
    Arguments[4] = (ULONG_PTR)FuzzSafeThreadStart;
    Arguments[5] = 0;
    Arguments[6] = createFlags;
    Arguments[7] = (ULONG_PTR)0;
    Arguments[8] = (ULONG_PTR)stackSize;
    Arguments[9] = (ULONG_PTR)maximumStackSize;
    Arguments[10] = 0;

    mutateIndex = FuzzRandom() % 8;

    switch (mutateIndex) {

    case 0:
        Arguments[1] = FuzzAccessData[FuzzRandom() % FUZZACCESS_COUNT];
        break;

    case 1:
        if (pObjectAttributes) {
            pObjectAttributes->Length = sizeof(OBJECT_ATTRIBUTES);
            pObjectAttributes->RootDirectory = NULL;
            pObjectAttributes->ObjectName = NULL;
            pObjectAttributes->Attributes = (ULONG)FuzzAttrData[FuzzRandom() % FUZZATTR_COUNT];
            pObjectAttributes->SecurityDescriptor = NULL;
            pObjectAttributes->SecurityQualityOfService = NULL;
            Arguments[2] = (ULONG_PTR)pObjectAttributes;
        }
        break;

    case 2:
    {
        static const ULONG_PTR safeCreateFlags[] = {
            0x00000001ui64,
            0x00000001ui64 | 0x00000004ui64,
            0x00000001ui64 | 0x00000040ui64,
            0x00000001ui64 | 0x00000080ui64
        };

        Arguments[6] = safeCreateFlags[FuzzRandom() % RTL_NUMBER_OF(safeCreateFlags)];
        break;
    }

    case 3:
    {
        static const ULONG_PTR zeroBitsValues[] = {
            0,
            1,
            0x10,
            0x20,
            0x1000
        };

        Arguments[7] = zeroBitsValues[FuzzRandom() % RTL_NUMBER_OF(zeroBitsValues)];
        break;
    }

    case 4:
    {
        static const SIZE_T stackSizes[] = {
            0,
            0x1000,
            0x2000,
            0x4000,
            0x10000
        };

        Arguments[8] = (ULONG_PTR)stackSizes[FuzzRandom() % RTL_NUMBER_OF(stackSizes)];
        break;
    }

    case 5:
    {
        static const SIZE_T maxStackSizes[] = {
            0,
            0x1000,
            0x4000,
            0x10000,
            0x40000
        };

        Arguments[9] = (ULONG_PTR)maxStackSizes[FuzzRandom() % RTL_NUMBER_OF(maxStackSizes)];
        break;
    }

    case 6:
    {
        static const ULONG_PTR safeArguments[] = {
            0,
            1,
            0x1234,
            0x10000
        };

        Arguments[5] = safeArguments[FuzzRandom() % RTL_NUMBER_OF(safeArguments)];
        break;
    }

    case 7:
        if ((FuzzRandom() % 4) == 0)
            Arguments[0] = 0;
        break;
    }

    Arguments[6] |= 0x00000001ui64;
    return TRUE;
}

/*
* FuzzGenerateParameter
*
* Purpose:
*
* Generate a parameter value for fuzzing based on parameter type and index.
*
*/
ULONG_PTR FuzzGenerateParameter(
    _In_ ULONG ParameterIndex,
    _In_ PARAM_TYPE_HINT TypeHint,
    _In_ BOOL IsWin32kSyscall,
    _In_ BOOL EnableParamsHeuristic,
    _In_ PBYTE FuzzStructBuffer
)
{
    ULONG variation;
    PBYTE structSlot;

    structSlot = FuzzGetParameterStructSlot(FuzzStructBuffer, ParameterIndex);

    if (!EnableParamsHeuristic) {
        return FuzzData[FuzzRandom() % FUZZDATA_COUNT];
    }

    variation = FuzzRandom() % 20;
    if (variation == 0) {
        return FuzzData[FuzzRandom() % FUZZDATA_COUNT];
    }

    switch (TypeHint) {
    case ParamTypeAddress:
    {
        static const ULONG addressBufferSizes[] = {
            sizeof(ULONG),
            sizeof(ULONG_PTR),
            16,
            32,
            64,
            128,
            256,
            512,
            1024,
            4096
        };

        ULONG addressMode;
        ULONG bufferSize;
        PBYTE buffer;

        addressMode = FuzzRandom() % 10;

        switch (addressMode) {
        case 0:
            return 0;

        case 1:
        case 2:
        case 3:
        case 4:
        case 5:
        case 6:
            bufferSize = addressBufferSizes[FuzzRandom() % _countof(addressBufferSizes)];
            buffer = (PBYTE)VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (buffer) {
                RtlSecureZeroMemory(buffer, bufferSize);
                if (!FuzzTrackAllocation(buffer, AllocTypeVirtualAlloc)) {
                    VirtualFree(buffer, 0, MEM_RELEASE);
                    return 0;
                }

                if (bufferSize >= sizeof(ULONG_PTR)) {
                    if ((FuzzRandom() % 3) == 0) {
                        *(PULONG_PTR)buffer = FuzzData[FuzzRandom() % FUZZDATA_COUNT];
                    }
                }

                if (bufferSize > 16 && (FuzzRandom() % 5) == 0) {
                    return (ULONG_PTR)(buffer + (((ULONG_PTR)FuzzRandom() % 8) + 1));
                }

                return (ULONG_PTR)buffer;
            }
            break;

        case 7:
            bufferSize = addressBufferSizes[FuzzRandom() % _countof(addressBufferSizes)];
            buffer = (PBYTE)VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (buffer) {
                if (!FuzzTrackAllocation(buffer, AllocTypeVirtualAlloc)) {
                    VirtualFree(buffer, 0, MEM_RELEASE);
                    return 0;
                }

                if (bufferSize >= sizeof(ULONG_PTR)) {
                    *(PULONG_PTR)buffer = 0x4141414141414141ui64;
                }
                if (bufferSize >= (2 * sizeof(ULONG_PTR))) {
                    *(PULONG_PTR)(buffer + bufferSize - sizeof(ULONG_PTR)) = 0x4242424242424242ui64;
                }

                return (ULONG_PTR)buffer;
            }
            break;
        }

        return FuzzAddrData[FuzzRandom() % FUZZADDR_COUNT];
    }

    case ParamTypeHandle:
        return FuzzHandleData[FuzzRandom() % FUZZHANDLE_COUNT];

    case ParamTypeStatus:
        if (variation < 5 && structSlot) {
            return (ULONG_PTR)CreateFuzzedIoStatusBlock(structSlot, FuzzGetRemainingSlotSize(ParameterIndex));
        }
        return FuzzStatusData[FuzzRandom() % FUZZSTATUS_COUNT];

    case ParamTypeAccess:
        return FuzzAccessData[FuzzRandom() % FUZZACCESS_COUNT];

    case ParamTypeFlag:
        if (variation < 15) {
            ULONG numBits;
            ULONG bit;
            ULONG_PTR result;
            ULONG_PTR usedBits;
            ULONG maxBits;
            ULONG i;

            numBits = (FuzzRandom() % 3) + 1;
            result = 0;
            usedBits = 0;
            maxBits = (ULONG)(sizeof(ULONG_PTR) * 8);

            for (i = 0; i < numBits; i++) {
                do {
                    bit = FuzzRandom() % maxBits;
                } while (usedBits & ((ULONG_PTR)1 << bit));

                usedBits |= ((ULONG_PTR)1 << bit);
                result |= ((ULONG_PTR)1 << bit);
            }

            return result;
        }
        return FuzzData[FuzzRandom() % FUZZDATA_COUNT];

    case ParamTypeUnicodeStr:
        return structSlot ? (ULONG_PTR)CreateFuzzedUnicodeString(structSlot, FuzzGetRemainingSlotSize(ParameterIndex)) : 0;

    case ParamTypeObjectAttr:
        return structSlot ? (ULONG_PTR)CreateFuzzedObjectAttributes(structSlot, FuzzGetRemainingSlotSize(ParameterIndex)) : 0;

    case ParamTypeToken:
        return FuzzTokenData[FuzzRandom() % FUZZTOKEN_COUNT];

    case ParamTypePrivilege:
        return structSlot ? (ULONG_PTR)CreateFuzzedTokenPrivileges(structSlot, FuzzGetRemainingSlotSize(ParameterIndex)) : 0;

    case ParamTypeInfoClass:
        return FuzzInfoClassData[FuzzRandom() % FUZZINFOCLASS_COUNT];

    case ParamTypeBufferSize:
        return FuzzBufSizeData[FuzzRandom() % FUZZBUFSIZE_COUNT];

    case ParamTypeTimeout:
        if (variation < 15) {
            return structSlot ? (ULONG_PTR)CreateFuzzedLargeInteger(structSlot, FuzzGetRemainingSlotSize(ParameterIndex)) : 0;
        }
        else {
            static const ULONG timeoutValues[] = {
                0, 1, 10, 100, 1000, 10000, 60000,
                0x7FFFFFFF, 0xFFFFFFFF, 0x80000000
            };
            return timeoutValues[FuzzRandom() % _countof(timeoutValues)];
        }

    case ParamTypeRetLength:
        if ((FuzzRandom() % 10) == 0) {
            return 0;
        }
        else {
            PULONG pLength;

            pLength = (PULONG)VirtualAlloc(NULL, sizeof(ULONG),
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            if (pLength) {
                *pLength = 0;
                if (!FuzzTrackAllocation(pLength, AllocTypeVirtualAlloc)) {
                    VirtualFree(pLength, 0, MEM_RELEASE);
                    return 0;
                }
                return (ULONG_PTR)pLength;
            }
            return 0;
        }

    case ParamTypeWinHandle:
        return FuzzWin32Data[FuzzRandom() % FUZZWIN32_COUNT];

    case ParamTypeGdiHandle:
        return FuzzGdiData[FuzzRandom() % FUZZGDI_COUNT];

    case ParamTypeSecDesc:
        return structSlot ? (ULONG_PTR)CreateFuzzedSecurityDescriptor(structSlot, FuzzGetRemainingSlotSize(ParameterIndex)) : 0;

    case ParamTypeClientId:
        return structSlot ? (ULONG_PTR)CreateFuzzedClientId(structSlot, FuzzGetRemainingSlotSize(ParameterIndex)) : 0;

    case ParamTypeKeyValue:
        return (ULONG_PTR)CreateFuzzedKeyValueParameter();

    case ParamTypeOutPtr:
    {
        static const ULONG outPtrSizes[] = {
            sizeof(ULONG),
            sizeof(HANDLE),
            sizeof(LARGE_INTEGER),
            32,
            64,
            128,
            512,
            1024,
            4096
        };

        ULONG bufferSize;
        PVOID buffer;

        bufferSize = outPtrSizes[FuzzRandom() % _countof(outPtrSizes)];
        buffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (buffer) {
            RtlSecureZeroMemory(buffer, bufferSize);
            if (!FuzzTrackAllocation(buffer, AllocTypeVirtualAlloc)) {
                VirtualFree(buffer, 0, MEM_RELEASE);
                return 0;
            }

            if (bufferSize <= sizeof(ULONG_PTR) && (FuzzRandom() % 2) == 0) {
                *(PULONG_PTR)buffer = (ULONG_PTR)0xBADF00DCAFEBABEui64;
            }

            return (ULONG_PTR)buffer;
        }
        return 0;
    }

    case ParamTypeGeneral:
    default:
        if (ParameterIndex >= 2 && ParameterIndex <= 4 && variation < 5 && structSlot) {
            ULONG structType;

            structType = FuzzRandom() % 3;

            switch (structType) {
            case 0:
                return (ULONG_PTR)CreateFuzzedProcessTimes(structSlot, FuzzGetRemainingSlotSize(ParameterIndex));
            case 1:
                return (ULONG_PTR)CreateFuzzedSectionImageInfo(structSlot, FuzzGetRemainingSlotSize(ParameterIndex));
            case 2:
                return (ULONG_PTR)CreateFuzzedLargeInteger(structSlot, FuzzGetRemainingSlotSize(ParameterIndex));
            }
        }

        if (IsWin32kSyscall && variation < 10) {
            if ((FuzzRandom() % 2) == 0) {
                return FuzzWin32Data[FuzzRandom() % FUZZWIN32_COUNT];
            }
            else {
                return FuzzGdiData[FuzzRandom() % FUZZGDI_COUNT];
            }
        }
        return FuzzData[FuzzRandom() % FUZZDATA_COUNT];
    }
}

/*
* FuzzDetectParameterTypes
*
* Purpose:
*
* Determine parameter types for all parameters of a syscall.
*
*/
VOID FuzzDetectParameterTypes(
    _In_ LPCSTR ServiceName,
    _In_ ULONG ParameterCount,
    _In_ BOOL IsWin32kSyscall,
    _Out_writes_(ParameterCount) PARAM_TYPE_HINT* TypeHints
)
{
    if (!ServiceName || !TypeHints || ParameterCount == 0) {
        return;
    }

    for (ULONG i = 0; i < ParameterCount; i++) {
        TypeHints[i] = FuzzGetSyscallParamType(ServiceName, i, IsWin32kSyscall);
    }
}

//
// Structure generation START
//

#pragma warning(push)
#pragma warning(disable: 6248)

/*
* CreateFuzzedSecurityDescriptor
*
* Purpose:
*
* Create a fuzzed SECURITY_DESCRIPTOR structure with various access control settings.
*
*/
PSECURITY_DESCRIPTOR CreateFuzzedSecurityDescriptor(
    _In_ BYTE* FuzzStructBuffer,
    _In_ SIZE_T BufferSize
)
{
    DWORD dwAclSize;
    ULONG mode;
    BOOL bResult = FALSE;
    PSECURITY_DESCRIPTOR pSD;
    PACL pAcl = NULL;
    SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
    SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;
    PSID pEveryoneSid = NULL;
    PSID pSystemSid = NULL;

    if (FuzzStructBuffer == NULL || BufferSize < SECURITY_DESCRIPTOR_MIN_LENGTH)
        return NULL;

    pSD = (PSECURITY_DESCRIPTOR)FuzzStructBuffer;
    mode = (ULONG)(FuzzRandom() % 8);

    RtlSecureZeroMemory(pSD, SECURITY_DESCRIPTOR_MIN_LENGTH);

    switch (mode) {
    case 0:
        return NULL;

    case 1:
        return (PSECURITY_DESCRIPTOR)FuzzAddrData[FuzzRandom() % FUZZADDR_COUNT];

    case 2:
        if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION))
            return NULL;
        return pSD;

    case 3:
        if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION))
            return NULL;

        bResult = SetSecurityDescriptorDacl(pSD, TRUE, NULL, FALSE);
        return bResult ? pSD : NULL;

    case 4:
        if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION))
            return NULL;

        if (!AllocateAndInitializeSid(&SIDAuthWorld, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &pEveryoneSid))
            return NULL;

        dwAclSize = sizeof(ACL) + sizeof(ACCESS_DENIED_ACE) + GetLengthSid(pEveryoneSid);
        pAcl = (PACL)VirtualAlloc(NULL, dwAclSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (pAcl) {
            if (!FuzzTrackAllocation(pAcl, AllocTypeVirtualAlloc)) {
                VirtualFree(pAcl, 0, MEM_RELEASE);
                FreeSid(pEveryoneSid);
                return NULL;
            }

            if (InitializeAcl(pAcl, dwAclSize, ACL_REVISION)) {
                if (AddAccessDeniedAce(pAcl, ACL_REVISION, GENERIC_ALL, pEveryoneSid)) {
                    if (SetSecurityDescriptorDacl(pSD, TRUE, pAcl, FALSE)) {
                        FreeSid(pEveryoneSid);
                        return pSD;
                    }
                }
            }
            FreeSid(pEveryoneSid);
        }
        return NULL;

    case 5:
        if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION))
            return NULL;

        if (!AllocateAndInitializeSid(&SIDAuthNT, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &pSystemSid))
            return NULL;

        if (SetSecurityDescriptorOwner(pSD, pSystemSid, FALSE)) {
            if (!FuzzTrackAllocation(pSystemSid, AllocTypeSid)) {
                FreeSid(pSystemSid);
                return NULL;
            }
            return pSD;
        }

        FreeSid(pSystemSid);
        return NULL;

    case 6:
        if (!InitializeSecurityDescriptor(pSD, 0xFF))
            return NULL;
        return pSD;

    case 7:
        if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION))
            return NULL;

        *(USHORT*)((PUCHAR)pSD + 2) = 0xFFFF;
        return pSD;

    default:
        if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION))
            return NULL;

        SetSecurityDescriptorDacl(pSD, TRUE, NULL, FALSE); //-V530
        SetSecurityDescriptorSacl(pSD, FALSE, NULL, FALSE);
        return pSD;
    }
}

/*
* CreateFuzzedUnicodeString
*
* Purpose:
*
* Create a fuzzed UNICODE_STRING structure. This randomly creates valid or invalid structures.
*
*/
PUNICODE_STRING CreateFuzzedUnicodeString(
    _In_ BYTE* FuzzStructBuffer,
    _In_ SIZE_T BufferSize
)
{
    USHORT length = 0, maxLength = 0;
    ULONG mode;
    PUNICODE_STRING UnicodeString;
    PWSTR buffer = NULL;
    PWSTR stringBuf;
    SIZE_T charsAvailable;

    if (FuzzStructBuffer == NULL || BufferSize < sizeof(UNICODE_STRING))
        return NULL;

    UnicodeString = (PUNICODE_STRING)FuzzStructBuffer;
    mode = (ULONG)(FuzzRandom() % 16);

    RtlSecureZeroMemory(UnicodeString, sizeof(UNICODE_STRING));
    stringBuf = (PWSTR)(FuzzStructBuffer + sizeof(UNICODE_STRING));
    charsAvailable = (BufferSize > sizeof(UNICODE_STRING)) ?
        ((BufferSize - sizeof(UNICODE_STRING)) / sizeof(WCHAR)) : 0;

    switch (mode) {
    case 0:
        return NULL;

    case 1:
        length = 0;
        maxLength = 0;
        buffer = NULL;
        break;

    case 2:
        if (charsAvailable < RTL_NUMBER_OF(L"\\??\\C:\\Windows\\System32\\kernel32.dll"))
            return NULL;

        _strcpy_w(stringBuf, L"\\??\\C:\\Windows\\System32\\kernel32.dll");
        length = (USHORT)(_strlen_w(stringBuf) * sizeof(WCHAR));
        maxLength = length + sizeof(WCHAR);
        buffer = stringBuf;
        break;

    case 3:
        if (charsAvailable < RTL_NUMBER_OF(L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion"))
            return NULL;

        _strcpy_w(stringBuf, L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion");
        length = (USHORT)(_strlen_w(stringBuf) * sizeof(WCHAR));
        maxLength = length + sizeof(WCHAR);
        buffer = stringBuf;
        break;

    case 4:
        if (charsAvailable < RTL_NUMBER_OF(L"BadString"))
            return NULL;

        _strcpy_w(stringBuf, L"BadString");
        length = 20;
        maxLength = 10;
        buffer = stringBuf;
        break;

    case 5:
        length = 10;
        maxLength = 10;
        buffer = NULL;
        break;

    case 6:
        length = 10;
        maxLength = 10;
        buffer = (PWSTR)FuzzAddrData[FuzzRandom() % FUZZADDR_COUNT];
        break;

    case 7:
        if (charsAvailable < RTL_NUMBER_OF(L"OddString"))
            return NULL;

        _strcpy_w(stringBuf, L"OddString");
        length = 7;
        maxLength = 7;
        buffer = stringBuf;
        break;

    case 8:
    {
        PWCHAR p;
        ULONG i, maxChars;

        if (charsAvailable < 2)
            return NULL;

        p = (PWCHAR)stringBuf;
        maxChars = (ULONG)((charsAvailable - 1) < 500 ? (charsAvailable - 1) : 500);

        for (i = 0; i < maxChars; i++) {
            *p++ = (WCHAR)(L'A' + (i % 26));
        }
        *p = 0;

        length = (USHORT)(maxChars * sizeof(WCHAR));
        maxLength = (USHORT)((maxChars + 1) * sizeof(WCHAR));
        buffer = stringBuf;
    }
    break;

    case 9:
        if (charsAvailable < RTL_NUMBER_OF(L"%s%n%p\x0000\x0001\xFFFF\t\r\n"))
            return NULL;

        _strcpy_w(stringBuf, L"%s%n%p\x0000\x0001\xFFFF\t\r\n");
        length = (USHORT)(_strlen_w(stringBuf) * sizeof(WCHAR));
        maxLength = length + sizeof(WCHAR);
        buffer = stringBuf;
        break;

    case 10:
        UnicodeString->Length = sizeof(UNICODE_STRING);
        UnicodeString->MaximumLength = sizeof(UNICODE_STRING);
        UnicodeString->Buffer = (PWSTR)UnicodeString;
        return UnicodeString;

    case 11:
        length = 6;
        maxLength = 8;
        buffer = (PWSTR)((BYTE*)UnicodeString - 4);
        break;

    case 12:
        if (charsAvailable == 0)
            return NULL;

        length = 8;
        maxLength = 16;
        buffer = (PWSTR)(((ULONG_PTR)stringBuf) | 1);
        break;

    case 13:
        length = (USHORT)0xFFFF;
        maxLength = (USHORT)0x0000;
        buffer = stringBuf;
        break;

    case 14:
        memset(UnicodeString, 0xFF, sizeof(UNICODE_STRING));
        return UnicodeString;

    case 15:
        if (charsAvailable < RTL_NUMBER_OF(L"ABC"))
            return NULL;

        _strcpy_w(stringBuf, L"ABC");
        length = 3;
        maxLength = 5;
        buffer = stringBuf;
        break;
    }

    UnicodeString->Length = length;
    UnicodeString->MaximumLength = maxLength;
    UnicodeString->Buffer = buffer;

    return UnicodeString;
}

/*
* CreateFuzzedObjectAttributes
*
* Purpose:
*
* Create a fuzzed OBJECT_ATTRIBUTES structure.
*
*/
POBJECT_ATTRIBUTES CreateFuzzedObjectAttributes(
    _In_ BYTE* FuzzStructBuffer,
    _In_ SIZE_T BufferSize
)
{
    ULONG mode;
    SIZE_T remainSize;
    POBJECT_ATTRIBUTES ObjectAttributes;
    PUNICODE_STRING ObjectName;
    PBYTE stringBuffer;

    if (FuzzStructBuffer == NULL || BufferSize < sizeof(OBJECT_ATTRIBUTES))
        return NULL;

    mode = (ULONG)(FuzzRandom() % 8);

    ObjectAttributes = (POBJECT_ATTRIBUTES)FuzzStructBuffer;
    RtlSecureZeroMemory(ObjectAttributes, sizeof(OBJECT_ATTRIBUTES));

    stringBuffer = (PBYTE)FuzzStructBuffer + sizeof(OBJECT_ATTRIBUTES);
    remainSize = BufferSize - sizeof(OBJECT_ATTRIBUTES);

    ObjectName = CreateFuzzedUnicodeString(stringBuffer, remainSize);

    switch (mode) {
    case 0:
        return NULL;

    case 1:
        ObjectAttributes->Length = sizeof(OBJECT_ATTRIBUTES) + 100;
        ObjectAttributes->RootDirectory = NULL;
        ObjectAttributes->ObjectName = ObjectName;
        ObjectAttributes->Attributes = 0;
        ObjectAttributes->SecurityDescriptor = NULL;
        ObjectAttributes->SecurityQualityOfService = NULL;
        break;

    case 2:
        ObjectAttributes->Length = sizeof(OBJECT_ATTRIBUTES);
        ObjectAttributes->RootDirectory = NULL;
        ObjectAttributes->ObjectName = ObjectName;
        ObjectAttributes->Attributes = (ULONG)FuzzAttrData[FuzzRandom() % FUZZATTR_COUNT];
        ObjectAttributes->SecurityDescriptor = NULL;
        ObjectAttributes->SecurityQualityOfService = NULL;
        break;

    case 3:
        ObjectAttributes->Length = sizeof(OBJECT_ATTRIBUTES);
        ObjectAttributes->RootDirectory = NULL;
        ObjectAttributes->ObjectName = ObjectName;
        ObjectAttributes->Attributes = 0;
        ObjectAttributes->SecurityDescriptor = (PVOID)FuzzAddrData[FuzzRandom() % FUZZADDR_COUNT];
        ObjectAttributes->SecurityQualityOfService = NULL;
        break;

    case 4:
        ObjectAttributes->Length = ((FuzzRandom() % 2) == 0) ?
            sizeof(OBJECT_ATTRIBUTES) : (ULONG)(FuzzRandom() % 256);
        ObjectAttributes->RootDirectory = (HANDLE)FuzzHandleData[FuzzRandom() % FUZZHANDLE_COUNT];
        ObjectAttributes->ObjectName = ObjectName;
        ObjectAttributes->Attributes = (ULONG)FuzzAttrData[FuzzRandom() % FUZZATTR_COUNT];
        ObjectAttributes->SecurityDescriptor = (PVOID)FuzzAddrData[FuzzRandom() % FUZZADDR_COUNT];
        ObjectAttributes->SecurityQualityOfService = (PVOID)FuzzAddrData[FuzzRandom() % FUZZADDR_COUNT];
        break;

    case 5:
        memset(ObjectAttributes, 0xAA, sizeof(OBJECT_ATTRIBUTES));
        break;

    case 6:
        ObjectAttributes->Length = sizeof(OBJECT_ATTRIBUTES);
        ObjectAttributes->ObjectName = (PUNICODE_STRING)ObjectAttributes; //-V1027
        ObjectAttributes->RootDirectory = NULL;
        ObjectAttributes->Attributes = 0;
        ObjectAttributes->SecurityDescriptor = NULL;
        ObjectAttributes->SecurityQualityOfService = NULL;
        break;

    case 7:
        ObjectAttributes->Length = sizeof(OBJECT_ATTRIBUTES);
        ObjectAttributes->ObjectName = NULL;
        ObjectAttributes->RootDirectory = NULL;
        ObjectAttributes->Attributes = 0;
        ObjectAttributes->SecurityDescriptor = NULL;
        ObjectAttributes->SecurityQualityOfService = NULL;
        break;
    }

    return ObjectAttributes;
}

/*
* CreateFuzzedTokenPrivileges
*
* Purpose:
*
* Create a fuzzed TOKEN_PRIVILEGES structure for NtAdjustPrivilegesToken testing.
*
*/
PTOKEN_PRIVILEGES CreateFuzzedTokenPrivileges(
    _In_ BYTE* FuzzStructBuffer,
    _In_ SIZE_T BufferSize
)
{
    ULONG i, variation, maxPrivileges, actualCount;
    PTOKEN_PRIVILEGES pPrivileges;

    if (FuzzStructBuffer == NULL || BufferSize < sizeof(ULONG))
        return NULL;

    maxPrivileges = (ULONG)((BufferSize - sizeof(ULONG)) / sizeof(LUID_AND_ATTRIBUTES));
    variation = (ULONG)(FuzzRandom() % 16);

    pPrivileges = (PTOKEN_PRIVILEGES)FuzzStructBuffer;
    RtlSecureZeroMemory(pPrivileges, BufferSize);

    switch (variation) {
    case 0:
        if (maxPrivileges < 1)
            return NULL;

        pPrivileges->PrivilegeCount = 1;
        pPrivileges->Privileges[0].Luid.LowPart = SE_DEBUG_PRIVILEGE;
        pPrivileges->Privileges[0].Luid.HighPart = 0;
        pPrivileges->Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        break;

    case 1:
        if (maxPrivileges < 3)
            return NULL;

        actualCount = 3;
        pPrivileges->PrivilegeCount = actualCount;
        for (i = 0; i < actualCount; ++i) {
            pPrivileges->Privileges[i].Luid.LowPart = SE_DEBUG_PRIVILEGE + i;
            pPrivileges->Privileges[i].Luid.HighPart = 0;
            pPrivileges->Privileges[i].Attributes = SE_PRIVILEGE_ENABLED;
        }
        break;

    case 2:
        pPrivileges->PrivilegeCount = 0;
        break;

    case 3:
        pPrivileges->PrivilegeCount = maxPrivileges + 1;
        actualCount = maxPrivileges;
        for (i = 0; i < actualCount; ++i) {
            pPrivileges->Privileges[i].Luid.LowPart = (ULONG)(FuzzRandom() % 35);
            pPrivileges->Privileges[i].Luid.HighPart = 0;
            pPrivileges->Privileges[i].Attributes = ((FuzzRandom() & 1) ? SE_PRIVILEGE_ENABLED : 0);
        }
        break;

    case 4:
        if (maxPrivileges < 1)
            return NULL;

        pPrivileges->PrivilegeCount = 1;
        pPrivileges->Privileges[0].Luid.LowPart = SE_DEBUG_PRIVILEGE;
        pPrivileges->Privileges[0].Luid.HighPart = 0;
        pPrivileges->Privileges[0].Attributes = 0;
        break;

    case 5:
        if (maxPrivileges < 1)
            return NULL;

        pPrivileges->PrivilegeCount = 1;
        pPrivileges->Privileges[0].Luid.LowPart = SE_DEBUG_PRIVILEGE;
        pPrivileges->Privileges[0].Luid.HighPart = 0;
        pPrivileges->Privileges[0].Attributes = 0xFFFFFFFF;
        break;

    case 6:
        if (maxPrivileges < 1)
            return NULL;

        pPrivileges->PrivilegeCount = 1;
        pPrivileges->Privileges[0].Luid.LowPart = SE_DEBUG_PRIVILEGE;
        pPrivileges->Privileges[0].Luid.HighPart = 0xFFFFFFFF;
        pPrivileges->Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        break;

    case 7:
        if (maxPrivileges < 1)
            return NULL;

        pPrivileges->PrivilegeCount = 1;
        pPrivileges->Privileges[0].Luid.LowPart = 0xFFFF;
        pPrivileges->Privileges[0].Luid.HighPart = 0;
        pPrivileges->Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        break;

    case 8:
        return NULL;

    case 9:
        return (PTOKEN_PRIVILEGES)0x7FFFFFFFFFFFFFFF;

    default:
        if (maxPrivileges < 1)
            return NULL;

        pPrivileges->PrivilegeCount = 1;
        pPrivileges->Privileges[0].Luid.LowPart = (ULONG)((FuzzRandom() % 35) + 1);
        pPrivileges->Privileges[0].Luid.HighPart = 0;
        pPrivileges->Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        break;
    }

    return pPrivileges;
}

/*
* CreateFuzzedIoStatusBlock
*
* Purpose:
*
* Create a fuzzed IO_STATUS_BLOCK structure for file and device I/O operations.
*
*/
PIO_STATUS_BLOCK CreateFuzzedIoStatusBlock(
    _In_ BYTE* FuzzStructBuffer,
    _In_ SIZE_T BufferSize
)
{
    ULONG variation;
    PIO_STATUS_BLOCK IoStatusBlock;

    if (FuzzStructBuffer == NULL || BufferSize < sizeof(IO_STATUS_BLOCK))
        return NULL;

    IoStatusBlock = (PIO_STATUS_BLOCK)FuzzStructBuffer;
    RtlSecureZeroMemory(IoStatusBlock, sizeof(IO_STATUS_BLOCK));

    variation = (ULONG)(FuzzRandom() % 8);

    switch (variation) {
    case 0:
        return NULL;

    case 1:
        break;

    case 2:
        IoStatusBlock->Status = STATUS_SUCCESS;
        IoStatusBlock->Information = 0;
        break;

    case 3:
        IoStatusBlock->Status = STATUS_PENDING;
        IoStatusBlock->Information = 0;
        break;

    case 4:
        IoStatusBlock->Status = STATUS_ACCESS_DENIED;
        IoStatusBlock->Information = 0;
        break;

    case 5:
        IoStatusBlock->Status = STATUS_SUCCESS;
        IoStatusBlock->Information = 1024;
        break;

    case 6:
        return (PIO_STATUS_BLOCK)FuzzAddrData[FuzzRandom() % FUZZADDR_COUNT];

    case 7:
        IoStatusBlock->Status = (NTSTATUS)FuzzStatusData[FuzzRandom() % FUZZSTATUS_COUNT];
        IoStatusBlock->Information = FuzzData[FuzzRandom() % FUZZDATA_COUNT];
        break;
    }

    return IoStatusBlock;
}

/*
* CreateFuzzedClientId
*
* Purpose:
*
* Create a fuzzed CLIENT_ID structure for thread/process operations.
*
*/
PCLIENT_ID CreateFuzzedClientId(
    _In_ BYTE* FuzzStructBuffer,
    _In_ SIZE_T BufferSize
)
{
    ULONG variation;
    PCLIENT_ID ClientId;

    if (FuzzStructBuffer == NULL || BufferSize < sizeof(CLIENT_ID))
        return NULL;

    variation = (ULONG)(FuzzRandom() % 6);
    ClientId = (PCLIENT_ID)FuzzStructBuffer;
    RtlSecureZeroMemory(ClientId, sizeof(CLIENT_ID));

    switch (variation) {
    case 0:
        return NULL;

    case 1:
        ClientId->UniqueProcess = UlongToHandle(GetCurrentProcessId());
        ClientId->UniqueThread = UlongToHandle(GetCurrentThreadId());
        break;

    case 2:
        ClientId->UniqueProcess = UlongToHandle(4);
        ClientId->UniqueThread = (HANDLE)FuzzHandleData[FuzzRandom() % FUZZHANDLE_COUNT];
        break;

    case 3:
        ClientId->UniqueProcess = UlongToHandle(0xFFFF);
        ClientId->UniqueThread = UlongToHandle(GetCurrentThreadId());
        break;

    case 4:
        ClientId->UniqueProcess = UlongToHandle(GetCurrentProcessId());
        ClientId->UniqueThread = UlongToHandle(0xFFFFFFFF);
        break;

    case 5:
        return (PCLIENT_ID)FuzzAddrData[FuzzRandom() % FUZZADDR_COUNT];
    }

    return ClientId;
}

/*
* CreateFuzzedLargeInteger
*
* Purpose:
*
* Create a fuzzed LARGE_INTEGER structure for time/interval operations.
*
*/
PLARGE_INTEGER CreateFuzzedLargeInteger(
    _In_ BYTE* FuzzStructBuffer,
    _In_ SIZE_T BufferSize
)
{
    ULONG variation;
    PLARGE_INTEGER LargeInteger;

    if (FuzzStructBuffer == NULL || BufferSize < sizeof(LARGE_INTEGER))
        return NULL;

    variation = (ULONG)(FuzzRandom() % 7);
    LargeInteger = (PLARGE_INTEGER)FuzzStructBuffer;
    RtlSecureZeroMemory(LargeInteger, sizeof(LARGE_INTEGER));

    switch (variation) {
    case 0:
        return NULL;

    case 1:
        LargeInteger->QuadPart = 0;
        break;

    case 2:
        LargeInteger->QuadPart = FuzzRandom() % 1000;
        break;

    case 3:
        LargeInteger->QuadPart = 0x7FFFFFFFFFFFFFFF;
        break;

    case 4:
        LargeInteger->QuadPart = -10000;
        break;

    case 5:
        return (PLARGE_INTEGER)FuzzAddrData[FuzzRandom() % FUZZADDR_COUNT];

    case 6:
    {
        static const LONGLONG specialTimes[] = {
            0,
            10000000,
            36000000000,
            864000000000,
            -10000000,
            0x7FFFFFFFFFFFFFFF,
            0x8000000000000000
        };

        LargeInteger->QuadPart = specialTimes[FuzzRandom() % RTL_NUMBER_OF(specialTimes)];
    }
    break;
    }

    return LargeInteger;
}

/*
* CreateFuzzedProcessTimes
*
* Purpose:
*
* Create fuzzed process times structure for NtQueryInformationProcess
*
*/
PKERNEL_USER_TIMES CreateFuzzedProcessTimes(
    _In_ BYTE* FuzzStructBuffer,
    _In_ SIZE_T BufferSize
)
{
    ULONG variation;
    PKERNEL_USER_TIMES Times;
    LARGE_INTEGER currentTime;

    if (FuzzStructBuffer == NULL || BufferSize < sizeof(KERNEL_USER_TIMES))
        return NULL;

    Times = (PKERNEL_USER_TIMES)FuzzStructBuffer;
    RtlZeroMemory(Times, sizeof(KERNEL_USER_TIMES));
    variation = (ULONG)(FuzzRandom() % 5);

    switch (variation) {
    case 0:
        return NULL;

    case 1:
        return (PKERNEL_USER_TIMES)FuzzAddrData[FuzzRandom() % FUZZADDR_COUNT];

    case 2:
        break;

    case 3:
        Times->CreateTime.QuadPart = 0x7FFFFFFFFFFFFFFF;
        Times->ExitTime.QuadPart = 0x7FFFFFFFFFFFFFFF;
        Times->KernelTime.QuadPart = 0x7FFFFFFFFFFFFFFF;
        Times->UserTime.QuadPart = 0x7FFFFFFFFFFFFFFF;
        break;

    case 4:
        NtQuerySystemTime(&currentTime);

        Times->CreateTime.QuadPart = currentTime.QuadPart - 10000000000i64;
        Times->ExitTime.QuadPart = 0;
        Times->KernelTime.QuadPart = 2500000;
        Times->UserTime.QuadPart = 5000000;
        break;
    }

    return Times;
}

/*
* CreateFuzzedSectionImageInfo
*
* Purpose:
*
* Create a fuzzed SECTION_IMAGE_INFORMATION structure
*
*/
PSECTION_IMAGE_INFORMATION CreateFuzzedSectionImageInfo(
    _In_ BYTE* FuzzStructBuffer,
    _In_ SIZE_T BufferSize
)
{
    ULONG variation;
    PSECTION_IMAGE_INFORMATION SectionInfo;

    if (FuzzStructBuffer == NULL || BufferSize < sizeof(SECTION_IMAGE_INFORMATION))
        return NULL;

    variation = (ULONG)(FuzzRandom() % 4);
    SectionInfo = (PSECTION_IMAGE_INFORMATION)FuzzStructBuffer;
    RtlZeroMemory(SectionInfo, sizeof(SECTION_IMAGE_INFORMATION));

    switch (variation) {
    case 0:
        return NULL;

    case 1:
        break;

    case 2:
        SectionInfo->TransferAddress = (PVOID)0x400000; //-V566
        SectionInfo->ZeroBits = 0;
        SectionInfo->MaximumStackSize = 0x100000;
        SectionInfo->CommittedStackSize = 0x10000;
        SectionInfo->SubSystemType = IMAGE_SUBSYSTEM_WINDOWS_GUI;
        SectionInfo->SubSystemMinorVersion = 0;
        SectionInfo->SubSystemMajorVersion = 6;
        SectionInfo->ImageCharacteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_DLL;
        SectionInfo->DllCharacteristics = IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
        SectionInfo->Machine = IMAGE_FILE_MACHINE_AMD64;
        SectionInfo->ImageContainsCode = TRUE;
        SectionInfo->LoaderFlags = 0;
        SectionInfo->ImageFileSize = 0x100000;
        SectionInfo->CheckSum = 0x12345;
        break;

    case 3:
        SectionInfo->TransferAddress = (PVOID)0xFFFFFFFFFFFFFFFF;
        SectionInfo->ZeroBits = 0xFF;
        SectionInfo->MaximumStackSize = 0xFFFFFFFF;
        SectionInfo->CommittedStackSize = 0xFFFFFFFF;
        SectionInfo->SubSystemType = 0xFF;
        SectionInfo->SubSystemMinorVersion = 0xFF;
        SectionInfo->SubSystemMajorVersion = 0xFF;
        SectionInfo->ImageCharacteristics = 0xFFFF;
        SectionInfo->DllCharacteristics = 0xFFFF;
        SectionInfo->Machine = 0xFFFF;
        SectionInfo->ImageContainsCode = TRUE;
        SectionInfo->LoaderFlags = 0xFFFFFFFF;
        SectionInfo->ImageFileSize = 0xFFFFFFFF;
        SectionInfo->CheckSum = 0xFFFFFFFF;
        break;
    }

    return SectionInfo;
}

/*
* CreateFuzzedKeyValueParameter
*
* Purpose:
*
* Create a fuzzed registry value structure
*
*/
PVOID CreateFuzzedKeyValueParameter(
    VOID
)
{
    BYTE* buf;
    ULONG variation, keyType;

    variation = (ULONG)FuzzRandom();
    keyType = variation % 10;

    if (keyType == 9) {
        return (PVOID)FuzzAddrData[FuzzRandom() % FUZZADDR_COUNT];
    }

    buf = (BYTE*)VirtualAlloc(NULL, MAX_KEYVALUE_BUFFER_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf)
        return NULL;

    if (!FuzzTrackAllocation(buf, AllocTypeVirtualAlloc)) {
        VirtualFree(buf, 0, MEM_RELEASE);
        return NULL;
    }

    RtlZeroMemory(buf, MAX_KEYVALUE_BUFFER_SIZE);

    switch (keyType) {
    case 0: {
        PKEY_VALUE_BASIC_INFORMATION info;
        ULONG maxNameLen;
        ULONG nameLen;
        ULONG i;

        info = (PKEY_VALUE_BASIC_INFORMATION)buf;
        maxNameLen = (MAX_KEYVALUE_BUFFER_SIZE - sizeof(*info) + sizeof(WCHAR)) / sizeof(WCHAR);
        nameLen = (variation >> 4) % (maxNameLen + 1);
        info->TitleIndex = (variation >> 8) & 0xFF;
        info->Type = (variation >> 16) & 0xF;
        info->NameLength = nameLen * sizeof(WCHAR);
        for (i = 0; i < info->NameLength / sizeof(WCHAR); ++i)
            info->Name[i] = (WCHAR)(L'A' + (variation + i) % 26);
        break;
    }
    case 1: {
        PKEY_VALUE_FULL_INFORMATION info;
        ULONG maxNameLen;
        ULONG nameLen;
        ULONG dataOffset;
        ULONG maxDataLen;
        ULONG dataLen;
        BYTE* data;
        ULONG i;

        info = (PKEY_VALUE_FULL_INFORMATION)buf;
        maxNameLen = (MAX_KEYVALUE_BUFFER_SIZE - sizeof(*info) + sizeof(WCHAR)) / sizeof(WCHAR);
        nameLen = (variation >> 5) % (maxNameLen + 1);
        info->NameLength = nameLen * sizeof(WCHAR);
        dataOffset = sizeof(*info) - sizeof(WCHAR) + info->NameLength;
        maxDataLen = (dataOffset < MAX_KEYVALUE_BUFFER_SIZE) ?
            (MAX_KEYVALUE_BUFFER_SIZE - dataOffset) : 0;
        dataLen = (variation >> 9) % (maxDataLen + 1);

        info->TitleIndex = (variation >> 12) & 0xFF;
        info->Type = (variation >> 20) & 0xF;
        info->DataLength = dataLen;
        info->DataOffset = dataOffset;

        for (i = 0; i < info->NameLength / sizeof(WCHAR); ++i)
            info->Name[i] = (WCHAR)(L'B' + (variation + i) % 26);

        data = buf + info->DataOffset;
        for (i = 0; i < dataLen && (info->DataOffset + i) < MAX_KEYVALUE_BUFFER_SIZE; ++i)
            data[i] = (BYTE)((variation >> (i % 16)) & 0xFF);
        break;
    }
    case 2: {
        PKEY_VALUE_PARTIAL_INFORMATION info;
        ULONG maxDataLen;
        ULONG dataLen;
        ULONG i;

        info = (PKEY_VALUE_PARTIAL_INFORMATION)buf;
        maxDataLen = (MAX_KEYVALUE_BUFFER_SIZE > sizeof(*info)) ?
            (MAX_KEYVALUE_BUFFER_SIZE - sizeof(*info) + 1) : 0;
        dataLen = (variation >> 4) % (maxDataLen + 1);
        info->TitleIndex = (variation >> 1) & 0xFF;
        info->Type = (variation >> 10) & 0xF;
        info->DataLength = dataLen;
        for (i = 0; i < dataLen; ++i)
            info->Data[i] = (UCHAR)((variation + i) & 0xFF);
        break;
    }
    case 3: {
        PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64 info;
        ULONG maxDataLen;
        ULONG dataLen;
        ULONG i;

        info = (PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64)buf;
        maxDataLen = (MAX_KEYVALUE_BUFFER_SIZE > sizeof(*info)) ?
            (MAX_KEYVALUE_BUFFER_SIZE - sizeof(*info) + 1) : 0;
        dataLen = (variation >> 2) % (maxDataLen + 1);
        info->Type = (variation >> 6) & 0xF;
        info->DataLength = dataLen;
        for (i = 0; i < dataLen; ++i)
            info->Data[i] = (UCHAR)(((variation >> (i % 8)) ^ 0xAA) & 0xFF);
        break;
    }
    case 4: {
        PKEY_VALUE_FULL_INFORMATION info;

        info = (PKEY_VALUE_FULL_INFORMATION)buf;
        info->TitleIndex = 0xFFFFFFFF;
        info->Type = 0xDEADBEEF;
        info->NameLength = 0x10000;
        info->DataLength = 0x10000;
        info->DataOffset = 0xFFFFFFF0;
        break;
    }
    case 5: {
        PKEY_VALUE_BASIC_INFORMATION info;

        info = (PKEY_VALUE_BASIC_INFORMATION)buf;
        info->TitleIndex = 0xFFFFFFFF;
        info->Type = 0x1BADB002;
        info->NameLength = 0xFFFFFFFC;
        break;
    }
    case 6: {
        PKEY_VALUE_PARTIAL_INFORMATION info;

        info = (PKEY_VALUE_PARTIAL_INFORMATION)buf;
        info->TitleIndex = 0xFFFFFFFF;
        info->Type = 0xABCD1234;
        info->DataLength = 0xFFFFFFFF;
        break;
    }
    case 7: {
        PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64 info;

        info = (PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64)buf;
        info->Type = 0xF00DFACE;
        info->DataLength = 0xFFFFFFFF;
        break;
    }
    case 8: {
        PKEY_VALUE_FULL_INFORMATION info;

        info = (PKEY_VALUE_FULL_INFORMATION)buf;
        info->TitleIndex = 0x0;
        info->Type = 0x0;
        info->NameLength = 0x80000000;
        info->DataLength = 0x80000000;
        info->DataOffset = 0x10;
        break;
    }
    default:
        break;
    }

    return buf;
}

#pragma warning(pop)

//
// Structure generation END
//
