/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2025 - 2026
*
*  TITLE:       FUZZ_PARAM.C
*
*  VERSION:     2.01
*
*  DATE:        14 Feb 2026
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

#ifdef _DEBUG
BOOL VerifySyscallDatabaseSorted(UINT DbType)
{
    SYSCALL_PARAM_INFO* Database = (DbType == 0) ? (SYSCALL_PARAM_INFO*)KnownNtSyscalls : (SYSCALL_PARAM_INFO*)KnownWin32kSyscalls;
    SYSCALL_PARAM_INFO* prev = Database;
    SYSCALL_PARAM_INFO* curr = Database + 1;

    while (curr->Name != NULL) {
        if (_strcmpi_a(prev->Name, curr->Name) > 0) {
            OutputDebugStringA(prev->Name);
            OutputDebugStringA("\n\r");
            return FALSE;
        }
        prev = curr;
        curr++;
    }
    return TRUE;
}
#endif

/*
* FuzzTrackAllocation
*
* Purpose:
*
* Track allocated memory so it can be freed even if the stack is corrupted.
*
*/
VOID FuzzTrackAllocation(
    _In_ PVOID Address,
    _In_ FUZZ_ALLOC_TYPE Type
)
{
    if (Address == NULL)
        return;

    while (InterlockedCompareExchange(&g_MemoryTracker.Lock, 1, 0) != 0) {
        YieldProcessor();
    }

    if (g_MemoryTracker.Count < MAX_FUZZING_ALLOCATIONS) {
        g_MemoryTracker.Addresses[g_MemoryTracker.Count] = Address;
        g_MemoryTracker.Types[g_MemoryTracker.Count] = Type;
        g_MemoryTracker.Count++;
    }

    InterlockedExchange(&g_MemoryTracker.Lock, 0);
}
/*
* FuzzCleanupAllocations
*
* Purpose:
*
* Free all tracked memory allocations.
* This is called from a separate context to handle stack corruption.
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
PARAM_TYPE_HINT FuzzSyscallBinarySearch(
    _In_ LPCSTR SyscallName,
    _In_ ULONG ParamIndex,
    _In_ const SYSCALL_PARAM_INFO* Database,
    _In_ ULONG DatabaseCount
)
{
    int left = 0;
    int right = (int)DatabaseCount - 1;
    int mid, result;

    while (left <= right) {
        mid = left + ((right - left) / 2);
        result = _strcmpi_a(SyscallName, Database[mid].Name);
        if (result == 0) {
            return Database[mid].ParamTypes[ParamIndex];
        }

        if (result < 0) {
            right = mid - 1;
        }
        else {
            left = mid + 1;
        }
    }

    return ParamTypeGeneral;
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

    result = FuzzSyscallBinarySearch(SyscallName, ParamIndex, pDatabase, databaseCount);

    if (result == ParamTypeGeneral) {
        return FuzzDetermineParameterTypeHeuristic(SyscallName, ParamIndex, IsWin32kSyscall);
    }

    return result;
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
    BOOL hasCreatePrefix = _strstr_a(SyscallName, "Create") != NULL;
    BOOL hasOpenPrefix = _strstr_a(SyscallName, "Open") != NULL;
    BOOL hasQueryPrefix = _strstr_a(SyscallName, "Query") != NULL;
    BOOL hasSetPrefix = _strstr_a(SyscallName, "Set") != NULL;
    BOOL hasEnumeratePrefix = _strstr_a(SyscallName, "Enumerate") != NULL;
    BOOL hasAllocPrefix = _strstr_a(SyscallName, "Allocate") != NULL;
    BOOL hasFreePrefix = _strstr_a(SyscallName, "Free") != NULL;
    BOOL hasGetPrefix = _strstr_a(SyscallName, "Get") != NULL;

    BOOL hasFileTerm = _strstr_a(SyscallName, "File") != NULL;
    BOOL hasKeyTerm = _strstr_a(SyscallName, "Key") != NULL;
    BOOL hasRegistryTerm = hasKeyTerm || _strstr_a(SyscallName, "Registry") != NULL;
    BOOL hasMemoryTerm = _strstr_a(SyscallName, "Memory") != NULL || _strstr_a(SyscallName, "Virtual") != NULL;
    BOOL hasProcessTerm = _strstr_a(SyscallName, "Process") != NULL;
    BOOL hasThreadTerm = _strstr_a(SyscallName, "Thread") != NULL;
    BOOL hasTokenTerm = _strstr_a(SyscallName, "Token") != NULL;
    BOOL hasInfoTerm = _strstr_a(SyscallName, "Information") != NULL;
    BOOL hasReadTerm = _strstr_a(SyscallName, "Read") != NULL;
    BOOL hasWriteTerm = _strstr_a(SyscallName, "Write") != NULL;
    BOOL hasSecurityTerm = _strstr_a(SyscallName, "Security") != NULL ||
        _strstr_a(SyscallName, "Sacl") != NULL ||
        _strstr_a(SyscallName, "Dacl") != NULL;
    BOOL hasTimeTerm = _strstr_a(SyscallName, "Time") != NULL ||
        _strstr_a(SyscallName, "Timer") != NULL ||
        _strstr_a(SyscallName, "Delay") != NULL ||
        _strstr_a(SyscallName, "Wait") != NULL;
    BOOL hasSectionTerm = _strstr_a(SyscallName, "Section") != NULL;
    BOOL hasValueTerm = _strstr_a(SyscallName, "Value") != NULL;
    BOOL hasClientTerm = _strstr_a(SyscallName, "Client") != NULL || _strstr_a(SyscallName, "PID") != NULL;
    BOOL hasPrivilegeTerm = _strstr_a(SyscallName, "Privilege") != NULL;

    BOOL isUserFunction = IsWin32kSyscall && _strstr_a(SyscallName, "NtUser") != NULL;
    BOOL isGdiFunction = IsWin32kSyscall && _strstr_a(SyscallName, "NtGdi") != NULL;
    BOOL hasWindowTerm = _strstr_a(SyscallName, "Window") != NULL;
    BOOL hasMenuTerm = _strstr_a(SyscallName, "Menu") != NULL;
    BOOL hasDCTerm = _strstr_a(SyscallName, "DC") != NULL;
    BOOL hasDrawTerm = _strstr_a(SyscallName, "Draw") != NULL ||
        _strstr_a(SyscallName, "Paint") != NULL ||
        _strstr_a(SyscallName, "Fill") != NULL;

    BOOL isFirstParam = (ParameterIndex == 0);
    BOOL isSecondParam = (ParameterIndex == 1);
    BOOL isThirdParam = (ParameterIndex == 2);
    BOOL isFourthParam = (ParameterIndex == 3);
    BOOL isFifthParam = (ParameterIndex == 4);
    BOOL isHighIndexParam = (ParameterIndex >= 5);

    // ========== SYSTEM-WIDE PATTERNS ==========

    // Security descriptor parameters
    if (hasSecurityTerm) {
        if (isThirdParam || isFourthParam) {
            return ParamTypeSecDesc;
        }
    }

    // Time and interval parameters
    if (hasTimeTerm) {
        if (isSecondParam || isThirdParam) {
            return ParamTypeTimeout; // Likely a LARGE_INTEGER time value
        }
    }

    // Section-related parameters
    if (hasSectionTerm) {
        if (isFirstParam) return ParamTypeHandle;
        if (isThirdParam || isFourthParam) return ParamTypeAddress;
        if (isSecondParam && hasQueryPrefix) return ParamTypeInfoClass;
    }

    // Client ID parameters for thread/process identification
    if ((hasProcessTerm || hasThreadTerm) && hasClientTerm) {
        if (isThirdParam || isFourthParam) {
            return ParamTypeClientId;
        }
    }

    // Privilege-related parameters
    if (hasPrivilegeTerm && (hasTokenTerm || hasSetPrefix)) {
        if (isSecondParam || isThirdParam) {
            return ParamTypePrivilege;
        }
    }

    // ========== WIN32K SYSCALLS ==========

    if (IsWin32kSyscall) {
        // User function parameter patterns
        if (isUserFunction) {
            if (isFirstParam) {
                if (hasWindowTerm || hasMenuTerm) {
                    return ParamTypeWinHandle;
                }
                if (hasCreatePrefix || hasOpenPrefix) {
                    return ParamTypeAddress; // Output handle pointer
                }

                return ParamTypeWinHandle; // Default for first param in NtUser
            }

            // String related parameters
            if ((isSecondParam || isThirdParam) &&
                (hasCreatePrefix || _strstr_a(SyscallName, "Name") != NULL ||
                    _strstr_a(SyscallName, "Text") != NULL))
            {
                return ParamTypeUnicodeStr;
            }

            // Common patterns for second parameters
            if (isSecondParam) {
                if (hasCreatePrefix || hasOpenPrefix) {
                    return ParamTypeAccess; // For Create/Open, second param often access rights
                }
                if (hasSetPrefix || hasQueryPrefix) {
                    return ParamTypeInfoClass; // For Set/Query, often info class
                }
                if (hasGetPrefix) {
                    return ParamTypeOutPtr; // For Get, often output buffer
                }
                return ParamTypeFlag; // Default fallback
            }

            // Output pointers in User calls
            if ((isThirdParam || isFourthParam) &&
                (hasGetPrefix || hasQueryPrefix)) {
                return ParamTypeOutPtr;
            }
        }

        // GDI function parameter patterns
        if (isGdiFunction) {
            if (isFirstParam) {
                if (hasDCTerm ||
                    _strstr_a(SyscallName, "Select") != NULL ||
                    hasDrawTerm)
                {
                    return ParamTypeGdiHandle;
                }

                if (hasCreatePrefix) {
                    return ParamTypeFlag; // Often width/height for creation
                }

                return ParamTypeGdiHandle; // Default for first param in NtGdi
            }

            // Common patterns for GDI parameters
            if (hasDrawTerm && (isSecondParam || isThirdParam || isFourthParam)) {
                return ParamTypeFlag; // Often coordinates or dimensions
            }

            if (isSecondParam &&
                (_strstr_a(SyscallName, "Select") != NULL ||
                    _strstr_a(SyscallName, "Get") != NULL))
            {
                return ParamTypeGdiHandle;
            }

            if (isSecondParam || isThirdParam) {
                if (_strstr_a(SyscallName, "Color") != NULL) {
                    return ParamTypeFlag; // COLORREF value
                }
                if (_strstr_a(SyscallName, "Create") != NULL ||
                    _strstr_a(SyscallName, "Set") != NULL)
                {
                    return ParamTypeFlag; // Properties for creation/setting
                }
            }
        }

        // General patterns for Win32k parameters
        if (isHighIndexParam) {
            // Common pattern: alternating address and flag/value
            return (ParameterIndex % 2 == 0) ? ParamTypeAddress : ParamTypeFlag;
        }
    }
    // ========== NT SYSCALLS ==========
    else {
        // ======= COMMON NT SYSCALL PATTERNS ========

        // Create/Open pattern - most common NT API pattern
        if (hasCreatePrefix || hasOpenPrefix) {
            if (isFirstParam) return ParamTypeAddress;  // Output handle pointer
            if (isSecondParam) return ParamTypeAccess;  // Access mask
            if (isThirdParam) return ParamTypeObjectAttr; // Object attributes
        }

        // Query pattern - second most common NT API pattern
        if (hasQueryPrefix || hasGetPrefix) {
            if (isFirstParam) {
                // Handle for object-specific queries, info class for system-wide
                return hasInfoTerm ? ParamTypeInfoClass : ParamTypeHandle;
            }

            if (isSecondParam && hasInfoTerm) {
                return ParamTypeInfoClass; // Information class
            }

            if (isThirdParam) return ParamTypeAddress; // Output buffer
            if (isFourthParam) return ParamTypeBufferSize; // Buffer size

            // Final parameter in query functions often returns length
            if (isFifthParam && hasInfoTerm) {
                return ParamTypeRetLength;
            }
        }

        // Set pattern
        if (hasSetPrefix) {
            if (isFirstParam) return ParamTypeHandle;

            if (isSecondParam && hasInfoTerm) {
                return ParamTypeInfoClass; // Information class
            }

            if (isThirdParam) return ParamTypeAddress; // Input buffer
            if (isFourthParam) return ParamTypeBufferSize; // Buffer size
        }

        // Memory operations
        if (hasMemoryTerm || hasAllocPrefix || hasFreePrefix) {
            if (isFirstParam) return ParamTypeHandle; // Process handle
            if (isSecondParam || isThirdParam) return ParamTypeAddress; // Memory address/pointer
            if (isFourthParam) return ParamTypeFlag; // Allocation type/flags
        }

        // File operations
        if (hasFileTerm || hasReadTerm || hasWriteTerm) {
            if (isFirstParam) return ParamTypeHandle;
            if (isSecondParam && (hasReadTerm || hasWriteTerm)) {
                return ParamTypeHandle; // Event handle
            }
            if (isFourthParam && hasFileTerm) return ParamTypeStatus; // IO_STATUS_BLOCK
        }

        // Registry patterns
        if (hasRegistryTerm) {
            if (isSecondParam && (hasQueryPrefix || hasSetPrefix)) {
                return ParamTypeUnicodeStr; // Key name
            }

            if (hasValueTerm && (isFourthParam || isFifthParam) && hasQueryPrefix) {
                return ParamTypeKeyValue;
            }
        }

        // Process/thread operations
        if (hasProcessTerm || hasThreadTerm) {
            if (isFirstParam) return ParamTypeHandle;
            if (isSecondParam && hasQueryPrefix) return ParamTypeInfoClass;
        }

        // Token operations
        if (hasTokenTerm) {
            if (isFirstParam) return ParamTypeToken;
            if ((hasSetPrefix || hasQueryPrefix) && isSecondParam) return ParamTypeInfoClass;

            // Special case for token privileges
            if (hasPrivilegeTerm && isThirdParam) {
                return ParamTypePrivilege;
            }
        }

        // Enumerate patterns
        if (hasEnumeratePrefix) {
            if (ParameterIndex >= 1 && ParameterIndex <= 3) return ParamTypeAddress;
        }
    }

    // Default patterns when no specific rule matches
    switch (ParameterIndex) {
    case 0:
        return IsWin32kSyscall ?
            (isUserFunction ? ParamTypeWinHandle : ParamTypeGdiHandle) :
            ParamTypeHandle;
    case 1:
    case 3:
    case 4:
        return ParamTypeFlag;
    case 2:
        return ParamTypeAddress;
    default:
        return (ParameterIndex % 2) ? ParamTypeFlag : ParamTypeAddress;
    }
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
    // If heuristics is disabled return random data
    if (!EnableParamsHeuristic) {
        return FuzzData[__rdtsc() % FUZZDATA_COUNT];
    }

    ULONG variation = __rdtsc() % 20;
    if (variation == 0) {
        return FuzzData[__rdtsc() % FUZZDATA_COUNT]; // 5% chance of using general fuzz data
    }

    // For the rest, use type-specific generation
    switch (TypeHint) {
    case ParamTypeAddress:
        if (variation < 15) { // 75% valid addresses
            // Allocate memory and return its address for certain indices
            if (ParameterIndex == 1 || ParameterIndex == 2 || ParameterIndex == 4) {
                PVOID buffer = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (buffer) {
                    RtlSecureZeroMemory(buffer, 4096);
                    FuzzTrackAllocation(buffer, AllocTypeVirtualAlloc);
                    return (ULONG_PTR)buffer;
                }
            }
        }
        return FuzzAddrData[__rdtsc() % FUZZADDR_COUNT];

    case ParamTypeHandle:
        return FuzzHandleData[__rdtsc() % FUZZHANDLE_COUNT];

    case ParamTypeStatus:
        // 25% chance of using fuzzed IO_STATUS_BLOCK
        if (variation < 5) {
            return (ULONG_PTR)CreateFuzzedIoStatusBlock(FuzzStructBuffer);
        }
        return FuzzStatusData[__rdtsc() % FUZZSTATUS_COUNT];

    case ParamTypeAccess:
        return FuzzAccessData[__rdtsc() % FUZZACCESS_COUNT];

    case ParamTypeFlag:
        if (variation < 15) {
            ULONG numBits = (__rdtsc() % 3) + 1;
            ULONG_PTR result = 0;
            ULONG usedBits = 0;
            ULONG bit;

            for (ULONG i = 0; i < numBits; i++) {
                do {
                    bit = __rdtsc() % 32;
                } while (usedBits & (1 << bit));
                usedBits |= (1 << bit);
                result |= (1ULL << bit);
            }

            return result;
        }
        return FuzzData[__rdtsc() % FUZZDATA_COUNT];

    case ParamTypeUnicodeStr:
        return (ULONG_PTR)CreateFuzzedUnicodeString(FuzzStructBuffer);

    case ParamTypeObjectAttr:
        return (ULONG_PTR)CreateFuzzedObjectAttributes(FuzzStructBuffer);

    case ParamTypeToken:
        return FuzzTokenData[__rdtsc() % FUZZTOKEN_COUNT];

    case ParamTypePrivilege:
        return (ULONG_PTR)CreateFuzzedTokenPrivileges(FuzzStructBuffer);

    case ParamTypeInfoClass:
        return FuzzInfoClassData[__rdtsc() % FUZZINFOCLASS_COUNT];

    case ParamTypeBufferSize:
        return FuzzBufSizeData[__rdtsc() % FUZZBUFSIZE_COUNT];

    case ParamTypeTimeout:
        // Use LARGE_INTEGER for timeouts
        if (variation < 15) { // 75% of the time use proper time structure
            return (ULONG_PTR)CreateFuzzedLargeInteger(FuzzStructBuffer);
        }
        else {
            static const ULONG timeoutValues[] = {
                0, 1, 10, 100, 1000, 10000, 60000,
                0x7FFFFFFF, 0xFFFFFFFF, 0x80000000 };
            return timeoutValues[__rdtsc() % _countof(timeoutValues)];
        }

    case ParamTypeRetLength:
        if (__rdtsc() % 10 == 0) {
            return 0; // NULL 10% of the time
        }
        else {
            PULONG pLength = (PULONG)VirtualAlloc(NULL, sizeof(ULONG),
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (pLength) {
                *pLength = 0;
                FuzzTrackAllocation(pLength, AllocTypeVirtualAlloc);
                return (ULONG_PTR)pLength;
            }
            return 0;
        }

    case ParamTypeWinHandle:
        return FuzzWin32Data[__rdtsc() % FUZZWIN32_COUNT];

    case ParamTypeGdiHandle:
        return FuzzGdiData[__rdtsc() % FUZZGDI_COUNT];

    case ParamTypeSecDesc:
        return (ULONG_PTR)CreateFuzzedSecurityDescriptor(FuzzStructBuffer);

    case ParamTypeClientId:
        return (ULONG_PTR)CreateFuzzedClientId(FuzzStructBuffer);

    case ParamTypeKeyValue:
        return (ULONG_PTR)CreateFuzzedKeyValueParameter();      

    case ParamTypeOutPtr:
        // Output pointers should be writable memory of varying sizes
    {
        // Different possible output pointer sizes to fuzz
        static const ULONG outPtrSizes[] = {
            sizeof(ULONG),        
            sizeof(HANDLE),       
            sizeof(LARGE_INTEGER),
            32,                   // Medium structure
            64,                   // Medium structure
            128,                  // Medium-large structure
            512,                  // Large structure
            1024,                 // Very large structure
            4096                  // Page-sized structure
        };

        ULONG bufferSize = outPtrSizes[__rdtsc() % _countof(outPtrSizes)];
        PVOID buffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (buffer) {
            RtlSecureZeroMemory(buffer, bufferSize);
            FuzzTrackAllocation(buffer, AllocTypeVirtualAlloc);

            // For small buffers, sometimes initialize with recognizable patterns
            if (bufferSize <= 8 && (__rdtsc() % 2) == 0) {
                *(PULONG_PTR)buffer = 0xBADF00DCAFEBABE;
            }

            return (ULONG_PTR)buffer;
        }
        return 0;
    }

    case ParamTypeGeneral:
    default:
        // Context-sensitive guessing for general parameters
        if (ParameterIndex >= 2 && ParameterIndex <= 4 && variation < 5) {
            // For indexes 2-4, sometimes use other complex structures that might be relevant
            ULONG structType = __rdtsc() % 3;

            switch (structType) {
            case 0:
                return (ULONG_PTR)CreateFuzzedProcessTimes(FuzzStructBuffer);
            case 1:
                return (ULONG_PTR)CreateFuzzedSectionImageInfo(FuzzStructBuffer);
            case 2:
                return (ULONG_PTR)CreateFuzzedLargeInteger(FuzzStructBuffer);
            }
        }

        if (IsWin32kSyscall && variation < 10) {
            if (__rdtsc() % 2 == 0) {
                return FuzzWin32Data[__rdtsc() % FUZZWIN32_COUNT];
            }
            else {
                return FuzzGdiData[__rdtsc() % FUZZGDI_COUNT];
            }
        }
        return FuzzData[__rdtsc() % FUZZDATA_COUNT];
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
    _In_ BYTE* FuzzStructBuffer
)
{
    PSECURITY_DESCRIPTOR pSD;
    PACL pAcl = NULL;
    DWORD dwAclSize;
    ULONG mode = __rdtsc() % 8;
    BOOL bResult = FALSE;
    SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
    SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;
    PSID pEveryoneSid = NULL;
    PSID pSystemSid = NULL;

    pSD = (PSECURITY_DESCRIPTOR)FuzzStructBuffer;

    switch (mode) {
    case 0: // NULL security descriptor
        return NULL;

    case 1: // Invalid security descriptor
        return (PSECURITY_DESCRIPTOR)FuzzAddrData[__rdtsc() % FUZZADDR_COUNT];

    case 2: // Empty but initialized security descriptor
        if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION))
            return NULL;
        return pSD;

    case 3: // Security descriptor with NULL DACL (everyone access)
        if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION))
            return NULL;

        bResult = SetSecurityDescriptorDacl(pSD, TRUE, NULL, FALSE);
        return bResult ? pSD : NULL;

    case 4: // Security descriptor with Deny-All DACL
        if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION))
            return NULL;

        // Create a PSID for Everyone
        if (!AllocateAndInitializeSid(&SIDAuthWorld, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &pEveryoneSid))
            return NULL;

        // Create a deny-all ACL
        dwAclSize = sizeof(ACL) + sizeof(ACCESS_DENIED_ACE) + GetLengthSid(pEveryoneSid);
        pAcl = (PACL)VirtualAlloc(NULL, dwAclSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (pAcl) {
            FuzzTrackAllocation(pAcl, AllocTypeVirtualAlloc);

            if (InitializeAcl(pAcl, dwAclSize, ACL_REVISION)) {
                // Add a deny ACE for Everyone
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

    case 5: // Security descriptor with owner but no DACL
        if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION))
            return NULL;

        // Create a PSID for Local System
        if (!AllocateAndInitializeSid(&SIDAuthNT, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &pSystemSid))
            return NULL;

        if (SetSecurityDescriptorOwner(pSD, pSystemSid, FALSE)) {
            // Note: We intentionally leak the SID here for fuzzing purposes
            FuzzTrackAllocation(pSystemSid, AllocTypeSid);
            return pSD;
        }
        FreeSid(pSystemSid);
        return NULL;

    case 6: // Invalid security descriptor with bad revision
        if (!InitializeSecurityDescriptor(pSD, 0xFF)) // Bad revision number
            return NULL;
        return pSD;

    case 7: // Security descriptor with corrupted control bits
        if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION))
            return NULL;

        *(USHORT*)((PUCHAR)pSD + 2) = 0xFFFF; // Corrupt control bits
        return pSD;

    default: // Minimal valid security descriptor
        if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION))
            return NULL;

        SetSecurityDescriptorDacl(pSD, TRUE, NULL, FALSE);
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
    _In_ BYTE* FuzzStructBuffer
)
{
    PUNICODE_STRING UnicodeString;
    PWSTR buffer = NULL, stringBuf;
    USHORT length = 0, maxLength = 0;
    ULONG mode = __rdtsc() % 16;

    UnicodeString = (PUNICODE_STRING)FuzzStructBuffer;
    stringBuf = (PWSTR)(FuzzStructBuffer + sizeof(UNICODE_STRING));

    // Create different variants of UNICODE_STRING
    switch (mode) {
    case 0: // NULL structure
        return NULL;

    case 1: // Valid empty string
        length = 0;
        maxLength = 0;
        buffer = NULL;
        break;

    case 2: // Valid string with content for file paths
        _strcpy_w((PWSTR)stringBuf, L"\\??\\C:\\Windows\\System32\\kernel32.dll");
        length = (USHORT)(_strlen_w((PWSTR)stringBuf) * sizeof(WCHAR));
        maxLength = length + sizeof(WCHAR);
        buffer = (PWSTR)stringBuf;
        break;

    case 3: // Valid string with registry path
        _strcpy_w((PWSTR)stringBuf, L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion");
        length = (USHORT)(_strlen_w((PWSTR)stringBuf) * sizeof(WCHAR));
        maxLength = length + sizeof(WCHAR);
        buffer = (PWSTR)stringBuf;
        break;

    case 4: // Invalid: Length > MaximumLength
        _strcpy_w((PWSTR)stringBuf, L"BadString");
        length = 20;
        maxLength = 10;
        buffer = (PWSTR)stringBuf;
        break;

    case 5: // Invalid: NULL buffer with non-zero length
        length = 10;
        maxLength = 10;
        buffer = NULL;
        break;

    case 6: // Invalid: Bad pointer
        length = 10;
        maxLength = 10;
        buffer = (PWSTR)FuzzAddrData[__rdtsc() % FUZZADDR_COUNT];
        break;

    case 7: // Odd lengths (unaligned)
        _strcpy_w((PWSTR)stringBuf, L"OddString");
        length = 7; // Intentionally wrong
        maxLength = 7;
        buffer = (PWSTR)stringBuf;
        break;

    case 8: // Very long string (boundary testing)
    {
        PWCHAR p = (PWCHAR)stringBuf;
        for (ULONG i = 0; i < 500; i++) {
            *p++ = L'A' + (i % 26);
        }
        *p = 0;
        length = 1000;
        maxLength = 1020;
        buffer = (PWSTR)stringBuf;
    }
    break;

    case 9: // String with special characters
        _strcpy_w((PWSTR)stringBuf, L"%s%n%p\x0000\x0001\xFFFF\t\r\n");
        length = (USHORT)(_strlen_w((PWSTR)stringBuf) * sizeof(WCHAR));
        maxLength = length + sizeof(WCHAR);
        buffer = (PWSTR)stringBuf;
        break;

    case 10: // String points to self
        UnicodeString->Length = sizeof(UNICODE_STRING);
        UnicodeString->MaximumLength = sizeof(UNICODE_STRING);
        UnicodeString->Buffer = (PWSTR)UnicodeString;
        break;

    case 11: // Buffer points inside parent
        length = 6;
        maxLength = 8;
        buffer = (PWSTR)((BYTE*)UnicodeString - 4);
        break;

    case 12: // Buffer is unaligned
        length = 8;
        maxLength = 16;
        buffer = (PWSTR)(((ULONG_PTR)stringBuf) | 1);
        break;

    case 13: // Length/MaximumLength overflows
        length = (USHORT)0xFFFF;
        maxLength = (USHORT)0x0000; // wrap-around
        buffer = stringBuf;
        break;

    case 14: // All fields are 0xFF
        memset(UnicodeString, 0xFF, sizeof(UNICODE_STRING));
        return UnicodeString;

    case 15: // Length not multiple of WCHAR
        _strcpy_w(stringBuf, L"ABC");
        length = 3; // Not divisible by 2
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
    _In_ BYTE* FuzzStructBuffer
)
{
    POBJECT_ATTRIBUTES ObjectAttributes;
    PUNICODE_STRING ObjectName;
    PBYTE stringBuffer;
    ULONG mode = __rdtsc() % 8;

    ObjectAttributes = (POBJECT_ATTRIBUTES)FuzzStructBuffer;
    stringBuffer = (PBYTE)FuzzStructBuffer + sizeof(OBJECT_ATTRIBUTES);

    // Create fuzzed object name
    ObjectName = CreateFuzzedUnicodeString(stringBuffer);

    // Create different variants
    switch (mode) {
    case 0: // NULL structure
        return NULL;

    case 1: // Invalid length
        ObjectAttributes->Length = sizeof(OBJECT_ATTRIBUTES) + 100;
        ObjectAttributes->RootDirectory = NULL;
        ObjectAttributes->ObjectName = ObjectName;
        ObjectAttributes->Attributes = 0;
        ObjectAttributes->SecurityDescriptor = NULL;
        ObjectAttributes->SecurityQualityOfService = NULL;
        break;

    case 2: // Valid but with random attributes
        ObjectAttributes->Length = sizeof(OBJECT_ATTRIBUTES);
        ObjectAttributes->RootDirectory = NULL;
        ObjectAttributes->ObjectName = ObjectName;
        ObjectAttributes->Attributes = (ULONG)FuzzAttrData[__rdtsc() % FUZZATTR_COUNT];
        ObjectAttributes->SecurityDescriptor = NULL;
        ObjectAttributes->SecurityQualityOfService = NULL;
        break;

    case 3: // Invalid security descriptor
        ObjectAttributes->Length = sizeof(OBJECT_ATTRIBUTES);
        ObjectAttributes->RootDirectory = NULL;
        ObjectAttributes->ObjectName = ObjectName;
        ObjectAttributes->Attributes = 0;
        ObjectAttributes->SecurityDescriptor = (PVOID)FuzzAddrData[__rdtsc() % FUZZADDR_COUNT];
        ObjectAttributes->SecurityQualityOfService = NULL;
        break;

    case 4: // All fields fuzzed
        ObjectAttributes->Length = (__rdtsc() % 2 == 0) ? sizeof(OBJECT_ATTRIBUTES) : (__rdtsc() % 256);
        ObjectAttributes->RootDirectory = (HANDLE)FuzzHandleData[__rdtsc() % FUZZHANDLE_COUNT];
        ObjectAttributes->ObjectName = ObjectName;
        ObjectAttributes->Attributes = (ULONG)FuzzAttrData[__rdtsc() % FUZZATTR_COUNT];
        ObjectAttributes->SecurityDescriptor = (PVOID)FuzzAddrData[__rdtsc() % FUZZADDR_COUNT];
        ObjectAttributes->SecurityQualityOfService = (PVOID)FuzzAddrData[__rdtsc() % FUZZADDR_COUNT];
        break;

    case 5: // All fields are 0xAA
        memset(ObjectAttributes, 0xAA, sizeof(OBJECT_ATTRIBUTES));
        break;

    case 6: // ObjectName points to ObjectAttributes itself
        ObjectAttributes->Length = sizeof(OBJECT_ATTRIBUTES);
        ObjectAttributes->ObjectName = (PUNICODE_STRING)ObjectAttributes;
        ObjectAttributes->RootDirectory = NULL;
        ObjectAttributes->Attributes = 0;
        ObjectAttributes->SecurityDescriptor = NULL;
        ObjectAttributes->SecurityQualityOfService = NULL;
        break;

    case 7: // ObjectName NULL, Length valid
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
    _In_ BYTE* FuzzStructBuffer
)
{
    PTOKEN_PRIVILEGES pPrivileges;
    ULONG variation;
    ULONG i, maxPrivileges, actualCount;

    maxPrivileges = (MAX_STRUCT_BUFFER_SIZE - sizeof(ULONG)) / sizeof(LUID_AND_ATTRIBUTES);

    // Use high variation for more patterns
    variation = __rdtsc() % 16;

    // Base struct at start of buffer
    pPrivileges = (PTOKEN_PRIVILEGES)FuzzStructBuffer;

    switch (variation) {
    case 0: // Valid privilege structure - single privilege
        pPrivileges->PrivilegeCount = 1;
        pPrivileges->Privileges[0].Luid.LowPart = SE_DEBUG_PRIVILEGE;
        pPrivileges->Privileges[0].Luid.HighPart = 0;
        pPrivileges->Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        break;

    case 1: // Valid privilege structure - multiple privileges
        actualCount = (maxPrivileges >= 3) ? 3 : 1;
        pPrivileges->PrivilegeCount = actualCount;
        for (i = 0; i < actualCount; ++i) {
            pPrivileges->Privileges[i].Luid.LowPart = SE_DEBUG_PRIVILEGE + i;
            pPrivileges->Privileges[i].Luid.HighPart = 0;
            pPrivileges->Privileges[i].Attributes = SE_PRIVILEGE_ENABLED;
        }
        break;

    case 2: // Valid structure with zero count (edge case)
        pPrivileges->PrivilegeCount = 0;
        break;

    case 3: // Invalid - count too high
        actualCount = maxPrivileges - 1;
        pPrivileges->PrivilegeCount = actualCount;
        for (i = 0; i < actualCount; ++i) {
            pPrivileges->Privileges[i].Luid.LowPart = (ULONG)(__rdtsc() % 35);
            pPrivileges->Privileges[i].Luid.HighPart = 0;
            pPrivileges->Privileges[i].Attributes = (__rdtsc() & 1) ? SE_PRIVILEGE_ENABLED : 0;
        }
        break;

    case 4: // Zero attributes 
        pPrivileges->PrivilegeCount = 1;
        pPrivileges->Privileges[0].Luid.LowPart = SE_DEBUG_PRIVILEGE;
        pPrivileges->Privileges[0].Luid.HighPart = 0;
        pPrivileges->Privileges[0].Attributes = 0; // No attributes
        break;

    case 5: // All attributes set 
        pPrivileges->PrivilegeCount = 1;
        pPrivileges->Privileges[0].Luid.LowPart = SE_DEBUG_PRIVILEGE;
        pPrivileges->Privileges[0].Luid.HighPart = 0;
        pPrivileges->Privileges[0].Attributes = 0xFFFFFFFF; // All bits set
        break;

    case 6: // Invalid LUIDs (high part)
        pPrivileges->PrivilegeCount = 1;
        pPrivileges->Privileges[0].Luid.LowPart = SE_DEBUG_PRIVILEGE;
        pPrivileges->Privileges[0].Luid.HighPart = 0xFFFFFFFF; // Invalid high part
        pPrivileges->Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        break;

    case 7: // Unusual privileges
        pPrivileges->PrivilegeCount = 1;
        pPrivileges->Privileges[0].Luid.LowPart = 0xFFFF; // Very high privilege number
        pPrivileges->Privileges[0].Luid.HighPart = 0;
        pPrivileges->Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        break;

    case 8: // NULL struct - rarely valid
        return NULL;

    case 9: // Boundary case - just below user/kernel space
        return (PTOKEN_PRIVILEGES)0x7FFFFFFFFFFFFFFF;

    default: // Standard valid structure
        pPrivileges->PrivilegeCount = 1;
        pPrivileges->Privileges[0].Luid.LowPart = (__rdtsc() % 35) + 1; // Random valid privilege
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
    _In_ BYTE* FuzzStructBuffer
)
{
    PIO_STATUS_BLOCK IoStatusBlock;
    ULONG variation = __rdtsc() % 8;

    IoStatusBlock = (PIO_STATUS_BLOCK)FuzzStructBuffer;

    switch (variation) {
    case 0: // NULL status block
        return NULL;

    case 1: // Valid but zeroed
        // Already zeroed above
        break;

    case 2: // Valid with successful status
        IoStatusBlock->Status = STATUS_SUCCESS;
        IoStatusBlock->Information = 0;
        break;

    case 3: // Status pending
        IoStatusBlock->Status = STATUS_PENDING;
        IoStatusBlock->Information = 0;
        break;

    case 4: // Error status
        IoStatusBlock->Status = STATUS_ACCESS_DENIED;
        IoStatusBlock->Information = 0;
        break;

    case 5: // Information contains byte count
        IoStatusBlock->Status = STATUS_SUCCESS;
        IoStatusBlock->Information = 1024; // Simulated bytes transferred
        break;

    case 6: // Invalid pointer
        return (PIO_STATUS_BLOCK)FuzzAddrData[__rdtsc() % FUZZADDR_COUNT];

    case 7: // Random values
        IoStatusBlock->Status = (NTSTATUS)FuzzStatusData[__rdtsc() % FUZZSTATUS_COUNT];
        IoStatusBlock->Information = FuzzData[__rdtsc() % FUZZDATA_COUNT];
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
    _In_ BYTE* FuzzStructBuffer
)
{
    PCLIENT_ID ClientId;
    ULONG variation = __rdtsc() % 6;

    ClientId = (PCLIENT_ID)FuzzStructBuffer;

    switch (variation) {
    case 0: // NULL client ID
        return NULL;

    case 1: // Current process/thread
        ClientId->UniqueProcess = UlongToHandle(GetCurrentProcessId());
        ClientId->UniqueThread = UlongToHandle(GetCurrentThreadId());
        break;

    case 2: // System process
        ClientId->UniqueProcess = UlongToHandle(4); // System process ID
        ClientId->UniqueThread = (HANDLE)FuzzHandleData[__rdtsc() % FUZZHANDLE_COUNT];
        break;

    case 3: // Invalid process/valid thread
        ClientId->UniqueProcess = UlongToHandle(0xFFFF);
        ClientId->UniqueThread = UlongToHandle(GetCurrentThreadId());
        break;
        
    case 4: // Valid process/invalid thread
        ClientId->UniqueProcess = UlongToHandle(GetCurrentProcessId());
        ClientId->UniqueThread = UlongToHandle(0xFFFFFFFF);
        break;

    case 5: // Invalid pointer
        return (PCLIENT_ID)FuzzAddrData[__rdtsc() % FUZZADDR_COUNT];
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
    _In_ BYTE* FuzzStructBuffer
)
{
    PLARGE_INTEGER LargeInteger;
    ULONG variation = __rdtsc() % 7;

    LargeInteger = (PLARGE_INTEGER)FuzzStructBuffer;

    switch (variation) {
    case 0: // NULL large integer
        return NULL;

    case 1: // Zero
        LargeInteger->QuadPart = 0;
        break;

    case 2: // Small positive value
        LargeInteger->QuadPart = __rdtsc() % 1000;
        break;

    case 3: // Large positive value
        LargeInteger->QuadPart = 0x7FFFFFFFFFFFFFFF;
        break;

    case 4: // Negative value
        LargeInteger->QuadPart = -10000;
        break;

    case 5: // Invalid pointer
        return (PLARGE_INTEGER)FuzzAddrData[__rdtsc() % FUZZADDR_COUNT];

    case 6: // Special time values
    {
        // Array of special time values in 100ns units
        static const LONGLONG specialTimes[] = {
            0,                      // Zero time
            10000000,               // 1 second
            36000000000,            // 1 hour
            864000000000,           // 1 day
            -10000000,              // -1 second (relative time)
            0x7FFFFFFFFFFFFFFF,     // Max positive value
            0x8000000000000000      // Min negative value
        };
        LargeInteger->QuadPart = specialTimes[__rdtsc() % 7];
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
    _In_ BYTE* FuzzStructBuffer
)
{
    PKERNEL_USER_TIMES Times;
    ULONG variation = __rdtsc() % 5;

    Times = (PKERNEL_USER_TIMES)FuzzStructBuffer;
    RtlZeroMemory(Times, sizeof(KERNEL_USER_TIMES));

    switch (variation) {
    case 0: // NULL
        return NULL;

    case 1: // Invalid pointer
        return (PKERNEL_USER_TIMES)FuzzAddrData[__rdtsc() % FUZZADDR_COUNT];

    case 2: // All zeros
        // Already zeroed
        break;

    case 3: // Invalid values (very large)
        Times->CreateTime.QuadPart = 0x7FFFFFFFFFFFFFFF;
        Times->ExitTime.QuadPart = 0x7FFFFFFFFFFFFFFF;
        Times->KernelTime.QuadPart = 0x7FFFFFFFFFFFFFFF;
        Times->UserTime.QuadPart = 0x7FFFFFFFFFFFFFFF;
        break;

    case 4: // Realistic values
    {
        LARGE_INTEGER currentTime;
        QueryPerformanceCounter(&currentTime);

        // Set a creation time in the past
        Times->CreateTime.QuadPart = currentTime.QuadPart - 10000000000; // 1000s ago
        Times->ExitTime.QuadPart = 0; // Not exited
        Times->KernelTime.QuadPart = 2500000; // 0.25s kernel time
        Times->UserTime.QuadPart = 5000000;   // 0.5s user time
    }
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
    _In_ BYTE* FuzzStructBuffer
)
{
    PSECTION_IMAGE_INFORMATION SectionInfo;
    ULONG variation = __rdtsc() % 4;

    SectionInfo = (PSECTION_IMAGE_INFORMATION)FuzzStructBuffer;
    RtlZeroMemory(SectionInfo, sizeof(SECTION_IMAGE_INFORMATION));

    switch (variation) {
    case 0: // NULL
        return NULL;

    case 1: // All zeros
        // Already zeroed
        break;

    case 2: // Realistic PE values
        SectionInfo->TransferAddress = (PVOID)0x400000;
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

    case 3: // Invalid values
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
PVOID CreateFuzzedKeyValueParameter(VOID)
{
    BYTE* buf = (BYTE*)VirtualAlloc(NULL, MAX_KEYVALUE_BUFFER_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf)
        return NULL;

    FuzzTrackAllocation(buf, AllocTypeVirtualAlloc);

    RtlZeroMemory(buf, MAX_KEYVALUE_BUFFER_SIZE);

    ULONG variation = (ULONG)__rdtsc();
    ULONG keyType = variation % 10;

    switch (keyType) {
    case 0: {
        //
        // KEY_VALUE_BASIC_INFORMATION - normal, buffer-safe
        //
        PKEY_VALUE_BASIC_INFORMATION info = (PKEY_VALUE_BASIC_INFORMATION)buf;
        ULONG maxNameLen = (MAX_KEYVALUE_BUFFER_SIZE - sizeof(*info) + sizeof(WCHAR)) / sizeof(WCHAR);
        ULONG nameLen = (variation >> 4) % (maxNameLen + 1);
        info->TitleIndex = (variation >> 8) & 0xFF;
        info->Type = (variation >> 16) & 0xF;
        info->NameLength = nameLen * sizeof(WCHAR);
        if (sizeof(*info) - sizeof(WCHAR) + info->NameLength > MAX_KEYVALUE_BUFFER_SIZE)
            info->NameLength = (MAX_KEYVALUE_BUFFER_SIZE - (sizeof(*info) - sizeof(WCHAR))) & ~1UL;
        for (ULONG i = 0; i < info->NameLength / sizeof(WCHAR); ++i)
            info->Name[i] = (WCHAR)(L'A' + (variation + i) % 26);
        break;
    }
    case 1: {
        //
        // KEY_VALUE_FULL_INFORMATION - normal, buffer-safe
        //
        PKEY_VALUE_FULL_INFORMATION info = (PKEY_VALUE_FULL_INFORMATION)buf;
        ULONG maxNameLen = (MAX_KEYVALUE_BUFFER_SIZE - sizeof(*info) + sizeof(WCHAR)) / sizeof(WCHAR);
        ULONG nameLen = (variation >> 5) % (maxNameLen + 1);
        info->NameLength = nameLen * sizeof(WCHAR);
        if (sizeof(*info) - sizeof(WCHAR) + info->NameLength > MAX_KEYVALUE_BUFFER_SIZE)
            info->NameLength = (MAX_KEYVALUE_BUFFER_SIZE - (sizeof(*info) - sizeof(WCHAR))) & ~1UL;

        ULONG dataOffset = sizeof(*info) - sizeof(WCHAR) + info->NameLength;
        ULONG maxDataLen = (dataOffset < MAX_KEYVALUE_BUFFER_SIZE)
            ? (MAX_KEYVALUE_BUFFER_SIZE - dataOffset)
            : 0;
        ULONG dataLen = (variation >> 9) % (maxDataLen + 1);

        info->TitleIndex = (variation >> 12) & 0xFF;
        info->Type = (variation >> 20) & 0xF;
        info->DataLength = dataLen;
        info->DataOffset = dataOffset;

        for (ULONG i = 0; i < info->NameLength / sizeof(WCHAR); ++i)
            info->Name[i] = (WCHAR)(L'B' + (variation + i) % 26);

        BYTE* data = buf + info->DataOffset;
        for (ULONG i = 0; i < dataLen && (info->DataOffset + i) < MAX_KEYVALUE_BUFFER_SIZE; ++i)
            data[i] = (BYTE)((variation >> (i % 16)) & 0xFF);
        break;
    }
    case 2: {
        //
        // KEY_VALUE_PARTIAL_INFORMATION - normal, buffer-safe
        //
        PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)buf;
        ULONG maxDataLen = (MAX_KEYVALUE_BUFFER_SIZE > sizeof(*info))
            ? (MAX_KEYVALUE_BUFFER_SIZE - sizeof(*info) + 1)
            : 0;
        ULONG dataLen = (variation >> 4) % (maxDataLen + 1);
        if (sizeof(*info) - 1 + dataLen > MAX_KEYVALUE_BUFFER_SIZE)
            dataLen = MAX_KEYVALUE_BUFFER_SIZE - (sizeof(*info) - 1);
        info->TitleIndex = (variation >> 1) & 0xFF;
        info->Type = (variation >> 10) & 0xF;
        info->DataLength = dataLen;
        for (ULONG i = 0; i < dataLen; ++i)
            info->Data[i] = (UCHAR)((variation + i) & 0xFF);
        break;
    }
    case 3: {
        //
        // KEY_VALUE_PARTIAL_INFORMATION_ALIGN64 - normal, buffer-safe
        //
        PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64 info = (PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64)buf;
        ULONG maxDataLen = (MAX_KEYVALUE_BUFFER_SIZE > sizeof(*info))
            ? (MAX_KEYVALUE_BUFFER_SIZE - sizeof(*info) + 1)
            : 0;
        ULONG dataLen = (variation >> 2) % (maxDataLen + 1);
        if (sizeof(*info) - 1 + dataLen > MAX_KEYVALUE_BUFFER_SIZE)
            dataLen = MAX_KEYVALUE_BUFFER_SIZE - (sizeof(*info) - 1);
        info->Type = (variation >> 6) & 0xF;
        info->DataLength = dataLen;
        for (ULONG i = 0; i < dataLen; ++i)
            info->Data[i] = (UCHAR)(((variation >> (i % 8)) ^ 0xAA) & 0xFF);
        break;
    }
    case 4: {
        //
        // KEY_VALUE_FULL_INFORMATION - edge/invalid metadata values
        //
        PKEY_VALUE_FULL_INFORMATION info = (PKEY_VALUE_FULL_INFORMATION)buf;
        info->TitleIndex = 0xFFFFFFFF;
        info->Type = 0xDEADBEEF;
        info->NameLength = 0x10000;
        info->DataLength = 0x10000;
        info->DataOffset = 0xFFFFFFF0;
        // Name/Data purposely uninitialized for edge testing
        break;
    }
    case 5: {
        //
        // KEY_VALUE_BASIC_INFORMATION - edge/invalid metadata values (NameLength, etc.)
        //
        PKEY_VALUE_BASIC_INFORMATION info = (PKEY_VALUE_BASIC_INFORMATION)buf;
        info->TitleIndex = 0xFFFFFFFF;
        info->Type = 0x1BADB002;
        info->NameLength = 0xFFFFFFFC;
        // Name purposely uninitialized for edge testing
        break;
    }
    case 6: {
        //
        // KEY_VALUE_PARTIAL_INFORMATION - edge/invalid DataLength
        //
        PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)buf;
        info->TitleIndex = 0xFFFFFFFF;
        info->Type = 0xABCD1234;
        info->DataLength = 0xFFFFFFFF;
        // Data purposely uninitialized
        break;
    }
    case 7: {
        //
        // KEY_VALUE_PARTIAL_INFORMATION_ALIGN64 - edge/invalid DataLength
        //
        PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64 info = (PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64)buf;
        info->Type = 0xF00DFACE;
        info->DataLength = 0xFFFFFFFF;
        // Data purposely uninitialized
        break;
    }
    case 8: {
        //
        // KEY_VALUE_FULL_INFORMATION - conflicting/overlapping metadata
        //
        PKEY_VALUE_FULL_INFORMATION info = (PKEY_VALUE_FULL_INFORMATION)buf;
        info->TitleIndex = 0x0;
        info->Type = 0x0;
        info->NameLength = 0x80000000;
        info->DataLength = 0x80000000;
        info->DataOffset = 0x10;
        // Name/Data purposely uninitialized
        break;
    }
    default:
        //
        // Return random fuzz data
        //
        return (PVOID)FuzzAddrData[__rdtsc() % FUZZADDR_COUNT];
    }

    return buf;
}

#pragma warning(pop)

//
// Structure generation END
//
