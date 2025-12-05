/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2025
*
*  TITLE:       FUZZ_DATA.H
*
*  VERSION:     2.01
*
*  DATE:        02 Dec 2025
*
*  Fuzzing data constants and Windows syscall database.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#define FUZZDATA_COUNT 18
const ULONG_PTR FuzzData[FUZZDATA_COUNT] = {
    0x0000000000000000,          // NULL
    0x0000000000000001,          // Minimum valid handle/pointer value
    0x000000000000DEAD,          // Random recognizable pattern
    0x0000000080000000,          // Kernel/user space boundary for 32-bit systems
    0x00007FFFFFFEFFFF,          // User memory space upper boundary (Windows x64)
    0x00007FFFFFFFFFFF,          // Last accessible user address
    0x0000800000000000,          // First kernel address (Windows x64)
    0x8000000000000000,          // Highest bit set (sign bit)
    0xFFFF080000000000,          // Typical kernel address range start
    0xFFFFF78000000000,          // Common Windows kernel address
    0xFFFFF80000000000,          // Windows kernel space base
    0xFFFFF80000000001,          // Windows kernel space base + 1
    0xFFFFFFFFFFFFFFFD,          // NTSTATUS: STATUS_UNSUCCESSFUL constant (-3)
    0xFFFFFFFFFFFFFFFC,          // NTSTATUS: STATUS_INVALID_HANDLE constant (-4)
    0xFFFFFFFFC0000001,          // NTSTATUS: STATUS_UNSUCCESSFUL mask
    0xFFFFFFFFFFFFFFFF,          // All bits set (-1)/INVALID_HANDLE_VALUE
    0xBAADF00DBAADF00D,          // Sentinel value (easily recognizable)
    0x4141414141414141           // ASCII "AAAAAAAA" (buffer overflow detection)
};

#define FUZZADDR_COUNT 5
const ULONG_PTR FuzzAddrData[FUZZADDR_COUNT] = {
    0x00000000001F0FFF,          // Reserved area near NULL
    0x000000007FFE0000,          // Shared user data page
    0x000000007FFE0030,          // Specific address in shared user data (KUSER_SHARED_DATA.SystemTime)
    0xFFFFF78000000000,          // HAL heap base
    0xFFFFF6FB7DBED000           // Known system-critical address
};

#define FUZZHANDLE_COUNT 10
const ULONG_PTR FuzzHandleData[FUZZHANDLE_COUNT] = {
    0x0000000000000000,          // NULL handle
    0x0000000000000004,          // Standard handle value (stdin)
    0xFFFFFFFFFFFFFFFC,          // Almost INVALID_HANDLE_VALUE
    0xFFFFFFFFFFFFFFFF,          // INVALID_HANDLE_VALUE
    0x0000000000000FFF,          // Low handle value
    0x0000000011111111,          // "Typical" handle pattern
    0x0000000000000014,          // Common NT handle pattern
    0x0000000000000018,          // Common NT handle pattern 
    0x000000000000001C,          // Common NT handle pattern
    0x0123456789ABCDEF           // Sequential pattern handle value
};

#define FUZZSTATUS_COUNT 10
const ULONG_PTR FuzzStatusData[FUZZSTATUS_COUNT] = {
    0x00000000C0000000,          // Generic failure bit
    0x0000000080000000,          // Customer code bit
    0x00000000C0000001,          // STATUS_UNSUCCESSFUL
    0x00000000C0000008,          // STATUS_INVALID_HANDLE
    0x00000000C0000005,          // STATUS_ACCESS_VIOLATION
    0x0000000001C00000,          // FACILITY_NTSSPI
    0x00000000C0000022,          // STATUS_ACCESS_DENIED
    0x00000000C0000034,          // STATUS_OBJECT_NAME_NOT_FOUND
    0x00000000C0000103,          // STATUS_PENDING
    0x0000000080000000           // STATUS_USER_APC
};

#define FUZZACCESS_COUNT 10
const ULONG_PTR FuzzAccessData[FUZZACCESS_COUNT] = {
    0x00000000,                  // No access
    0x00000001,                  // FILE_READ_DATA/PROCESS_TERMINATE
    0x00000002,                  // FILE_WRITE_DATA/PROCESS_CREATE_THREAD
    0x00000004,                  // FILE_APPEND_DATA/PROCESS_SET_SESSIONID
    0x00000008,                  // FILE_READ_EA/PROCESS_VM_OPERATION
    0x10000000,                  // GENERIC_READ
    0x20000000,                  // GENERIC_WRITE
    0x80000000,                  // GENERIC_ALL
    0x000F0000,                  // STANDARD_RIGHTS_REQUIRED
    0x001F0000,                  // STANDARD_RIGHTS_ALL
};

#define FUZZATTR_COUNT 9
const ULONG_PTR FuzzAttrData[FUZZATTR_COUNT] = {
    0x00000001,                  // OBJ_INHERIT
    0x00000002,                  // OBJ_PERMANENT
    0x00000004,                  // OBJ_EXCLUSIVE
    0x00000008,                  // OBJ_CASE_INSENSITIVE
    0x00000040,                  // OBJ_OPENIF
    0x00000100,                  // OBJ_KERNEL_HANDLE
    0x00000080,                  // OBJ_FORCE_ACCESS_CHECK
    0x00000400,                  // OBJ_IGNORE_IMPERSONATED_DEVICEMAP
    0x00001000                   // OBJ_DONT_REPARSE
};

#define FUZZINFOCLASS_COUNT 12
const ULONG_PTR FuzzInfoClassData[FUZZINFOCLASS_COUNT] = {
    0x0000000000000000,          // Class 0 (often BasicInformation)
    0x0000000000000001,          // Class 1 (often FileNameInformation)
    0x0000000000000002,          // Class 2
    0x0000000000000005,          // Class 5 (ProcessInformation)
    0x0000000000000007,          // Class 7
    0x000000000000000A,          // Class 10 (often used)
    0x0000000000000011,          // Class 17
    0x000000000000001F,          // Class 31
    0x00000000000000FF,          // Class 255 (boundary)
    0x0000000000010000,          // Class 65536 (high value)
    0x0000000080000001,          // High bit set
    0x00000000FFFFFFFF           // All bits set
};

#define FUZZTOKEN_COUNT 10
const ULONG_PTR FuzzTokenData[FUZZTOKEN_COUNT] = {
    0x0000000000000000,          // NULL token
    0xFFFFFFFFFFFFFFFF,          // INVALID_HANDLE_VALUE
    0xffffffffc0000001,          // Known bug parameter
    0x0000000000000004,          // Common token handle value
    0x0000000000000008,          // Common token handle value
    0x000000000000000C,          // Common token handle value
    0x0000000000000010,          // Common token handle value
    0xFFFFFFFE00000000,          // High bit pattern
    0x00000001FFFFFFFF           // Low bit pattern
};

#define FUZZBUFSIZE_COUNT 10
const ULONG_PTR FuzzBufSizeData[FUZZBUFSIZE_COUNT] = {
    0x0000000000000000,          // Zero size buffer
    0x0000000000000001,          // 1 byte - too small for most structures
    0x0000000000000002,          // 2 bytes
    0x0000000000000004,          // 4 bytes - sizeof(ULONG)
    0x0000000000000008,          // 8 bytes - sizeof(ULONG_PTR) on x64
    0x0000000000000010,          // 16 bytes - common small structure
    0x0000000000000100,          // 256 bytes
    0x0000000000001000,          // 4K - page size
    0x0000000000001001,          // 4K + 1 - just over page size
    0x00000000001FFFFF           // ~2MB - large buffer
};

// Win32k specific values for window handles, etc.
#define FUZZWIN32_COUNT 10
const ULONG_PTR FuzzWin32Data[FUZZWIN32_COUNT] = {
    0x0000000000000000,          // NULL HWND
    0x0000000000000001,          // HWND_DESKTOP
    0xFFFFFFFFFFFFFFFF,          // HWND_BROADCAST
    0x0000000000000003,          // HWND_MESSAGE
    0x0000000000000005,          // Common HWND value
    0x000000000000CAFE,          // Random handle value
    0x0000000000010001,          // Valid-looking handle pattern
    0x0000CAFE0000BEEF,          // Invalid handle pattern
    0xFFFF000000000000,          // High Word mask pattern
    0x0000FFFF00000000           // Middle Word mask pattern
};

// Win32k GDI specific data values
#define FUZZGDI_COUNT 6
const ULONG_PTR FuzzGdiData[FUZZGDI_COUNT] = {
    0x0000000000000000,          // NULL HDC/HBRUSH/etc
    0x0000000010001000,          // Typical GDI handle value
    0x0000000000000001,          // Stock_DC_Brush or similar
    0x00000000ABCDEF12,          // Random but recognizable
    0x0000000000000142,          // HORZRES system metric
    0x0000000100000001           // High bit pattern for handles
};

// NT Syscalls
const SYSCALL_PARAM_INFO KnownNtSyscalls[] = {
    {"NtAccessCheck", {ParamTypeAddress, ParamTypeHandle, ParamTypeAccess, ParamTypeAddress, ParamTypeAddress, ParamTypeAddress, ParamTypeAddress, ParamTypeAddress}},
    {"NtAccessCheckByType", {ParamTypeAddress, ParamTypeAddress, ParamTypeAddress, ParamTypeAccess, ParamTypeAddress, ParamTypeAddress, ParamTypeFlag, ParamTypeAddress, ParamTypeAddress, ParamTypeAddress, ParamTypeAddress}},
    {"NtAdjustPrivilegesToken", {ParamTypeToken, ParamTypeFlag, ParamTypePrivilege, ParamTypeBufferSize, ParamTypeAddress, ParamTypeRetLength}},
    {"NtAlertResumeThread", {ParamTypeHandle, ParamTypeAddress}},
    {"NtAlertThreadByThreadId", {ParamTypeHandle}},
    {"NtAllocateVirtualMemory", {ParamTypeHandle, ParamTypeAddress, ParamTypeFlag, ParamTypeAddress, ParamTypeFlag, ParamTypeFlag}},
    {"NtAllocateVirtualMemoryEx", {ParamTypeHandle, ParamTypeAddress, ParamTypeAddress, ParamTypeFlag, ParamTypeFlag, ParamTypeAddress, ParamTypeFlag}},
    {"NtAlpcAcceptConnectPort", {ParamTypeAddress, ParamTypeHandle, ParamTypeFlag, ParamTypeObjectAttr, ParamTypeAddress, ParamTypeAddress, ParamTypeAddress, ParamTypeAddress, ParamTypeFlag}},
    {"NtAlpcCreatePort", {ParamTypeAddress, ParamTypeObjectAttr, ParamTypeAddress}},
    {"NtAlpcCreatePortSection", {ParamTypeHandle, ParamTypeFlag, ParamTypeHandle, ParamTypeFlag, ParamTypeAddress, ParamTypeAddress}},
    {"NtAlpcDeletePortSection", {ParamTypeHandle, ParamTypeFlag, ParamTypeAddress}},
    {"NtAlpcDisconnectPort", {ParamTypeHandle, ParamTypeFlag}},
    {"NtAlpcOpenSenderProcess", {ParamTypeAddress, ParamTypeHandle, ParamTypeAddress, ParamTypeFlag, ParamTypeAccess, ParamTypeHandle}},
    {"NtAreMappedFilesTheSame", {ParamTypeAddress, ParamTypeAddress}},
    {"NtCallbackReturn", {ParamTypeAddress, ParamTypeBufferSize, ParamTypeStatus}},
    {"NtCallEnclave", {ParamTypeAddress, ParamTypeFlag, ParamTypeAddress, ParamTypeFlag, ParamTypeAddress}},
    {"NtCommitComplete", {ParamTypeHandle, ParamTypeAddress}},
    {"NtCommitEnlistment", {ParamTypeHandle, ParamTypeAddress}},
    {"NtCommitRegistryTransaction", {ParamTypeHandle, ParamTypeFlag}},
    {"NtCommitTransaction", {ParamTypeHandle, ParamTypeFlag}},
    {"NtCompactKeys", {ParamTypeHandle, ParamTypeFlag}},
    {"NtCompareObjects", {ParamTypeHandle, ParamTypeHandle}},
    {"NtCompareSigningLevels", {ParamTypeFlag, ParamTypeFlag}},
    {"NtCompressKey", {ParamTypeHandle}},
    {"NtConnectPort", {ParamTypeAddress, ParamTypeUnicodeStr, ParamTypeAddress, ParamTypeAddress, ParamTypeFlag, ParamTypeFlag, ParamTypeAddress, ParamTypeAddress}},
    {"NtContinue", {ParamTypeAddress, ParamTypeFlag}},
    {"NtCreateDebugObject", {ParamTypeAddress, ParamTypeAccess, ParamTypeObjectAttr, ParamTypeFlag}},
    {"NtCreateDirectoryObject", {ParamTypeAddress, ParamTypeAccess, ParamTypeObjectAttr}},
    {"NtCreateDirectoryObjectEx", {ParamTypeAddress, ParamTypeAccess, ParamTypeObjectAttr, ParamTypeHandle, ParamTypeFlag}},
    {"NtCreateEnclave", {ParamTypeHandle, ParamTypeAddress, ParamTypeAddress, ParamTypeAddress, ParamTypeFlag, ParamTypeAddress, ParamTypeFlag, ParamTypeAddress, ParamTypeFlag}},
    {"NtCreateEnlistment", {ParamTypeAddress, ParamTypeAccess, ParamTypeHandle, ParamTypeHandle, ParamTypeObjectAttr, ParamTypeFlag, ParamTypeFlag, ParamTypeAddress}},
    {"NtCreateEvent", {ParamTypeAddress, ParamTypeAccess, ParamTypeObjectAttr, ParamTypeFlag, ParamTypeFlag}},
    {"NtCreateFile", {ParamTypeAddress, ParamTypeAccess, ParamTypeObjectAttr, ParamTypeStatus, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeHandle, ParamTypeFlag, ParamTypeAddress, ParamTypeFlag}},
    {"NtCreateIoCompletion", {ParamTypeAddress, ParamTypeAccess, ParamTypeObjectAttr, ParamTypeFlag}},
    {"NtCreateIRTimer", {ParamTypeAddress, ParamTypeAccess}},
    {"NtCreateKey", {ParamTypeAddress, ParamTypeAccess, ParamTypeObjectAttr, ParamTypeFlag, ParamTypeUnicodeStr, ParamTypeFlag, ParamTypeAddress}},
    {"NtCreateKeyedEvent", {ParamTypeAddress, ParamTypeAccess, ParamTypeObjectAttr, ParamTypeFlag}},
    {"NtCreateKeyTransacted", {ParamTypeAddress, ParamTypeAccess, ParamTypeObjectAttr, ParamTypeFlag, ParamTypeUnicodeStr, ParamTypeFlag, ParamTypeHandle, ParamTypeAddress}},
    {"NtCreateMailslotFile", {ParamTypeAddress, ParamTypeAccess, ParamTypeObjectAttr, ParamTypeStatus, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeAddress}},
    {"NtCreateMutant", {ParamTypeAddress, ParamTypeAccess, ParamTypeObjectAttr, ParamTypeFlag}},
    {"NtCreateNamedPipeFile", {ParamTypeAddress, ParamTypeAccess, ParamTypeObjectAttr, ParamTypeStatus, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeAddress}},
    {"NtCreatePagingFile", {ParamTypeUnicodeStr, ParamTypeAddress, ParamTypeAddress, ParamTypeFlag}},
    {"NtCreatePartition", {ParamTypeAddress, ParamTypeHandle, ParamTypeFlag, ParamTypeFlag}},
    {"NtCreatePrivateNamespace", {ParamTypeAddress, ParamTypeAccess, ParamTypeObjectAttr, ParamTypeAddress}},
    {"NtCreateProcess", {ParamTypeAddress, ParamTypeAccess, ParamTypeObjectAttr, ParamTypeHandle, ParamTypeFlag, ParamTypeHandle, ParamTypeHandle, ParamTypeHandle}},
    {"NtCreateProcessEx", {ParamTypeAddress, ParamTypeAccess, ParamTypeObjectAttr, ParamTypeHandle, ParamTypeFlag, ParamTypeHandle, ParamTypeHandle, ParamTypeHandle, ParamTypeFlag}},
    {"NtCreateProfile", {ParamTypeAddress, ParamTypeHandle, ParamTypeAddress, ParamTypeFlag, ParamTypeFlag, ParamTypeAddress, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag}},
    {"NtCreateProfileEx", {ParamTypeAddress, ParamTypeHandle, ParamTypeAddress, ParamTypeAddress, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeAddress, ParamTypeFlag, ParamTypeFlag}},
    {"NtCreateRegistryTransaction", {ParamTypeAddress, ParamTypeAccess, ParamTypeObjectAttr, ParamTypeFlag}},
    {"NtCreateResourceManager", {ParamTypeAddress, ParamTypeAccess, ParamTypeHandle, ParamTypeAddress, ParamTypeObjectAttr, ParamTypeFlag, ParamTypeUnicodeStr}},
    {"NtCreateSection", {ParamTypeAddress, ParamTypeAccess, ParamTypeObjectAttr, ParamTypeAddress, ParamTypeFlag, ParamTypeFlag, ParamTypeHandle}},
    {"NtCreateSemaphore", {ParamTypeAddress, ParamTypeAccess, ParamTypeObjectAttr, ParamTypeFlag, ParamTypeFlag}},
    {"NtCreateSymbolicLinkObject", {ParamTypeAddress, ParamTypeAccess, ParamTypeObjectAttr, ParamTypeUnicodeStr}},
    {"NtCreateThread", {ParamTypeAddress, ParamTypeAccess, ParamTypeObjectAttr, ParamTypeHandle, ParamTypeAddress, ParamTypeAddress, ParamTypeAddress, ParamTypeFlag}},
    {"NtCreateThreadEx", {ParamTypeAddress, ParamTypeAccess, ParamTypeObjectAttr, ParamTypeHandle, ParamTypeAddress, ParamTypeAddress, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeAddress}},
    {"NtCreateTimer", {ParamTypeAddress, ParamTypeAccess, ParamTypeObjectAttr, ParamTypeFlag}},
    {"NtCreateTransaction", {ParamTypeAddress, ParamTypeAccess, ParamTypeObjectAttr, ParamTypeAddress, ParamTypeHandle, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeAddress, ParamTypeUnicodeStr}},
    {"NtCreateTransactionManager", {ParamTypeAddress, ParamTypeAccess, ParamTypeObjectAttr, ParamTypeUnicodeStr, ParamTypeFlag, ParamTypeFlag}},
    {"NtCreateUserProcess", {ParamTypeAddress, ParamTypeAddress, ParamTypeAccess, ParamTypeAccess, ParamTypeObjectAttr, ParamTypeObjectAttr, ParamTypeFlag, ParamTypeFlag, ParamTypeAddress, ParamTypeAddress, ParamTypeAddress}},
    {"NtCreateWnfStateName", {ParamTypeAddress, ParamTypeFlag, ParamTypeAddress, ParamTypeFlag, ParamTypeAddress, ParamTypeFlag, ParamTypeAccess}},
    {"NtDebugActiveProcess", {ParamTypeHandle, ParamTypeHandle}},
    {"NtDebugContinue", {ParamTypeHandle, ParamTypeAddress, ParamTypeStatus}},
    {"NtDeleteAtom", {ParamTypeFlag}},
    {"NtDeleteBootEntry", {ParamTypeFlag}},
    {"NtDeleteDriverEntry", {ParamTypeFlag}},
    {"NtDeleteFile", {ParamTypeObjectAttr}},
    {"NtDeleteKey", {ParamTypeHandle}},
    {"NtDeletePrivateNamespace", {ParamTypeHandle}},
    {"NtDeleteValueKey", {ParamTypeHandle, ParamTypeUnicodeStr}},
    {"NtDeviceIoControlFile", {ParamTypeHandle, ParamTypeHandle, ParamTypeAddress, ParamTypeAddress, ParamTypeStatus, ParamTypeFlag, ParamTypeAddress, ParamTypeFlag, ParamTypeAddress, ParamTypeFlag}},
    {"NtDisableLastKnownGood", {0}},
    {"NtDisplayString", {ParamTypeUnicodeStr}},
    {"NtDuplicateObject", {ParamTypeHandle, ParamTypeHandle, ParamTypeHandle, ParamTypeAddress, ParamTypeAccess, ParamTypeFlag, ParamTypeFlag}},
    {"NtDuplicateToken", {ParamTypeHandle, ParamTypeAccess, ParamTypeObjectAttr, ParamTypeFlag, ParamTypeFlag, ParamTypeAddress}},
    {"NtEnableLastKnownGood", {0}},
    {"NtEnumerateBootEntries", {ParamTypeAddress, ParamTypeAddress}},
    {"NtEnumerateDriverEntries", {ParamTypeAddress, ParamTypeAddress}},
    {"NtEnumerateKey", {ParamTypeHandle, ParamTypeFlag, ParamTypeFlag, ParamTypeAddress, ParamTypeFlag, ParamTypeAddress}},
    {"NtEnumerateSystemEnvironmentValuesEx", {ParamTypeFlag, ParamTypeAddress, ParamTypeAddress}},
    {"NtEnumerateTransactionObject", {ParamTypeHandle, ParamTypeFlag, ParamTypeAddress, ParamTypeFlag, ParamTypeAddress}},
    {"NtEnumerateValueKey", {ParamTypeHandle, ParamTypeFlag, ParamTypeFlag, ParamTypeAddress, ParamTypeFlag, ParamTypeAddress}},
    {"NtExtendSection", {ParamTypeHandle, ParamTypeAddress}},
    {"NtFilterBootOption", {ParamTypeFlag, ParamTypeFlag, ParamTypeAddress, ParamTypeFlag, ParamTypeAddress}},
    {"NtFilterToken", {ParamTypeHandle, ParamTypeFlag, ParamTypeAddress, ParamTypeAddress, ParamTypeAddress, ParamTypeAddress}},
    {"NtFilterTokenEx", {ParamTypeHandle, ParamTypeFlag, ParamTypeAddress, ParamTypeAddress, ParamTypeAddress, ParamTypeAddress, ParamTypeAddress, ParamTypeAddress, ParamTypeAddress, ParamTypeAddress}},
    {"NtFlushBuffersFile", {ParamTypeHandle, ParamTypeStatus}},
    {"NtFlushBuffersFileEx", {ParamTypeHandle, ParamTypeFlag, ParamTypeAddress, ParamTypeFlag, ParamTypeStatus}},
    {"NtFlushKey", {ParamTypeHandle}},
    {"NtFlushProcessWriteBuffers", {0}},
    {"NtFlushVirtualMemory", {ParamTypeHandle, ParamTypeAddress, ParamTypeAddress, ParamTypeStatus}},
    {"NtFreeVirtualMemory", {ParamTypeHandle, ParamTypeAddress, ParamTypeAddress, ParamTypeFlag}},
    {"NtFreezeRegistry", {ParamTypeFlag}},
    {"NtFreezeTransactions", {ParamTypeAddress, ParamTypeAddress}},
    {"NtFsControlFile", {ParamTypeHandle, ParamTypeHandle, ParamTypeAddress, ParamTypeAddress, ParamTypeStatus, ParamTypeFlag, ParamTypeAddress, ParamTypeFlag, ParamTypeAddress, ParamTypeFlag}},
    {"NtGetCachedSigningLevel", {ParamTypeHandle, ParamTypeAddress, ParamTypeAddress, ParamTypeAddress, ParamTypeAddress, ParamTypeAddress}},
    {"NtGetContextThread", {ParamTypeHandle, ParamTypeAddress}},
    {"NtGetDevicePowerState", {ParamTypeHandle, ParamTypeAddress}},
    {"NtGetMUIRegistryInfo", {ParamTypeFlag, ParamTypeAddress, ParamTypeAddress}},
    {"NtGetNextProcess", {ParamTypeHandle, ParamTypeAccess, ParamTypeFlag, ParamTypeFlag, ParamTypeAddress}},
    {"NtGetNextThread", {ParamTypeHandle, ParamTypeHandle, ParamTypeAccess, ParamTypeFlag, ParamTypeFlag, ParamTypeAddress}},
    {"NtGetNlsSectionPtr", {ParamTypeFlag, ParamTypeFlag, ParamTypeAddress, ParamTypeAddress, ParamTypeAddress}},
    {"NtGetNotificationResourceManager", {ParamTypeHandle, ParamTypeAddress, ParamTypeAddress, ParamTypeAddress, ParamTypeAddress, ParamTypeFlag, ParamTypeFlag}},
    {"NtGetWriteWatch", {ParamTypeHandle, ParamTypeFlag, ParamTypeAddress, ParamTypeFlag, ParamTypeAddress, ParamTypeAddress, ParamTypeAddress}},
    {"NtImpersonateAnonymousToken", {ParamTypeHandle}},
    {"NtImpersonateThread", {ParamTypeHandle, ParamTypeHandle, ParamTypeAddress}},
    {"NtInitializeNlsFiles", {ParamTypeAddress, ParamTypeAddress, ParamTypeAddress}},
    {"NtInitializeRegistry", {ParamTypeFlag}},
    {"NtIsSystemResumeAutomatic", {0}},
    {"NtIsUILanguageComitted", {0}},
    {"NtListenPort", {ParamTypeHandle, ParamTypeAddress}},
    {"NtLoadDriver", {ParamTypeUnicodeStr}},
    {"NtLoadKey", {ParamTypeObjectAttr, ParamTypeObjectAttr}},
    {"NtLoadKey2", {ParamTypeObjectAttr, ParamTypeObjectAttr, ParamTypeFlag}},
    {"NtLoadKey3", {ParamTypeObjectAttr, ParamTypeObjectAttr, ParamTypeFlag, ParamTypeFlag, ParamTypeHandle, ParamTypeFlag, ParamTypeHandle, ParamTypeFlag, ParamTypeFlag}},
    {"NtLoadKeyEx", {ParamTypeObjectAttr, ParamTypeObjectAttr, ParamTypeFlag, ParamTypeHandle, ParamTypeHandle, ParamTypeAccess, ParamTypeAddress, ParamTypeFlag}},
    {"NtLockFile", {ParamTypeHandle, ParamTypeHandle, ParamTypeAddress, ParamTypeAddress, ParamTypeStatus, ParamTypeAddress, ParamTypeAddress, ParamTypeAddress, ParamTypeFlag, ParamTypeFlag}},
    {"NtLockProductActivationKeys", {ParamTypeAddress, ParamTypeAddress}},
    {"NtLockRegistryKey", {ParamTypeHandle}},
    {"NtLockVirtualMemory", {ParamTypeHandle, ParamTypeAddress, ParamTypeAddress, ParamTypeFlag}},
    {"NtMakePermanentObject", {ParamTypeHandle}},
    {"NtMakeTemporaryObject", {ParamTypeHandle}},
    {"NtMapCMFModule", {ParamTypeFlag, ParamTypeFlag, ParamTypeAddress, ParamTypeAddress, ParamTypeAddress, ParamTypeAddress}},
    {"NtMapUserPhysicalPages", {ParamTypeAddress, ParamTypeAddress, ParamTypeAddress}},
    {"NtMapUserPhysicalPagesScatter", {ParamTypeAddress, ParamTypeAddress, ParamTypeAddress}},
    {"NtMapViewOfSection", {ParamTypeHandle, ParamTypeHandle, ParamTypeAddress, ParamTypeFlag, ParamTypeFlag, ParamTypeAddress, ParamTypeAddress, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag}},
    {"NtMapViewOfSectionEx", {ParamTypeHandle, ParamTypeHandle, ParamTypeAddress, ParamTypeAddress, ParamTypeFlag, ParamTypeFlag, ParamTypeAddress}},
    {"NtNotifyChangeDirectoryFile", {ParamTypeHandle, ParamTypeHandle, ParamTypeAddress, ParamTypeAddress, ParamTypeStatus, ParamTypeAddress, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag}},
    {"NtNotifyChangeKey", {ParamTypeHandle, ParamTypeHandle, ParamTypeAddress, ParamTypeAddress, ParamTypeStatus, ParamTypeFlag, ParamTypeFlag, ParamTypeAddress, ParamTypeFlag, ParamTypeFlag}},
    {"NtNotifyChangeMultipleKeys", {ParamTypeHandle, ParamTypeFlag, ParamTypeObjectAttr, ParamTypeHandle, ParamTypeAddress, ParamTypeAddress, ParamTypeStatus, ParamTypeFlag, ParamTypeFlag, ParamTypeAddress, ParamTypeFlag, ParamTypeFlag}},
    {"NtOpenDirectoryObject", {ParamTypeAddress, ParamTypeAccess, ParamTypeObjectAttr}},
    {"NtOpenEnlistment", {ParamTypeAddress, ParamTypeAccess, ParamTypeHandle, ParamTypeAddress, ParamTypeObjectAttr}},
    {"NtOpenEvent", {ParamTypeAddress, ParamTypeAccess, ParamTypeObjectAttr}},
    {"NtOpenFile", {ParamTypeAddress, ParamTypeAccess, ParamTypeObjectAttr, ParamTypeStatus, ParamTypeFlag, ParamTypeFlag}},
    {"NtOpenIoCompletion", {ParamTypeAddress, ParamTypeAccess, ParamTypeObjectAttr}},
    {"NtOpenKey", {ParamTypeAddress, ParamTypeAccess, ParamTypeObjectAttr}},
    {"NtOpenKeyedEvent", {ParamTypeAddress, ParamTypeAccess, ParamTypeObjectAttr}},
    {"NtOpenKeyEx", {ParamTypeAddress, ParamTypeAccess, ParamTypeObjectAttr, ParamTypeFlag}},
    {"NtOpenKeyTransacted", {ParamTypeAddress, ParamTypeAccess, ParamTypeObjectAttr, ParamTypeHandle}},
    {"NtOpenKeyTransactedEx", {ParamTypeAddress, ParamTypeAccess, ParamTypeObjectAttr, ParamTypeFlag, ParamTypeHandle}},
    {"NtOpenMutant", {ParamTypeAddress, ParamTypeAccess, ParamTypeObjectAttr}},
    {"NtOpenObjectAuditAlarm", {ParamTypeUnicodeStr, ParamTypeAddress, ParamTypeUnicodeStr, ParamTypeUnicodeStr, ParamTypeAddress, ParamTypeAddress, ParamTypeHandle, ParamTypeAccess, ParamTypeAccess, ParamTypeAddress, ParamTypeFlag, ParamTypeFlag}},
    {"NtOpenPartition", {ParamTypeAddress, ParamTypeAccess, ParamTypeObjectAttr}},
    {"NtOpenPrivateNamespace", {ParamTypeAddress, ParamTypeAccess, ParamTypeObjectAttr, ParamTypeAddress}},
    {"NtOpenProcess", {ParamTypeAddress, ParamTypeAccess, ParamTypeObjectAttr, ParamTypeStatus}},
    {"NtOpenProcessToken", {ParamTypeHandle, ParamTypeAccess, ParamTypeAddress}},
    {"NtOpenProcessTokenEx", {ParamTypeHandle, ParamTypeAccess, ParamTypeFlag, ParamTypeAddress}},
    {"NtOpenRegistryTransaction", {ParamTypeAddress, ParamTypeAccess, ParamTypeObjectAttr}},
    {"NtOpenResourceManager", {ParamTypeAddress, ParamTypeAccess, ParamTypeHandle, ParamTypeAddress, ParamTypeObjectAttr}},
    {"NtOpenSection", {ParamTypeAddress, ParamTypeAccess, ParamTypeObjectAttr}},
    {"NtOpenSemaphore", {ParamTypeAddress, ParamTypeAccess, ParamTypeObjectAttr}},
    {"NtOpenSession", {ParamTypeAddress, ParamTypeAccess, ParamTypeObjectAttr}},
    {"NtOpenSymbolicLinkObject", {ParamTypeAddress, ParamTypeAccess, ParamTypeObjectAttr}},
    {"NtOpenThread", {ParamTypeAddress, ParamTypeAccess, ParamTypeObjectAttr, ParamTypeStatus}},
    {"NtOpenThreadToken", {ParamTypeHandle, ParamTypeAccess, ParamTypeFlag, ParamTypeAddress}},
    {"NtOpenThreadTokenEx", {ParamTypeHandle, ParamTypeAccess, ParamTypeFlag, ParamTypeFlag, ParamTypeAddress}},
    {"NtOpenTimer", {ParamTypeAddress, ParamTypeAccess, ParamTypeObjectAttr}},
    {"NtOpenTransaction", {ParamTypeAddress, ParamTypeAccess, ParamTypeObjectAttr, ParamTypeAddress, ParamTypeHandle}},
    {"NtOpenTransactionManager", {ParamTypeAddress, ParamTypeAccess, ParamTypeObjectAttr, ParamTypeUnicodeStr, ParamTypeObjectAttr, ParamTypeFlag}},
    {"NtPlugPlayControl", {ParamTypeFlag, ParamTypeAddress, ParamTypeFlag}},
    {"NtPowerInformation", {ParamTypeFlag, ParamTypeAddress, ParamTypeBufferSize, ParamTypeAddress, ParamTypeBufferSize}},
    {"NtPrepareComplete", {ParamTypeHandle, ParamTypeAddress}},
    {"NtPrepareEnlistment", {ParamTypeHandle, ParamTypeAddress}},
    {"NtPrePrepareComplete", {ParamTypeHandle, ParamTypeAddress}},
    {"NtPrePrepareEnlistment", {ParamTypeHandle, ParamTypeAddress}},
    {"NtPropagationComplete", {ParamTypeHandle, ParamTypeFlag, ParamTypeFlag, ParamTypeAddress}},
    {"NtPropagationFailed", {ParamTypeHandle, ParamTypeFlag, ParamTypeStatus}},
    {"NtPulseEvent", {ParamTypeHandle, ParamTypeAddress}},
    {"NtQueryAttributesFile", {ParamTypeObjectAttr, ParamTypeAddress}},
    {"NtQueryBootEntryOrder", {ParamTypeAddress, ParamTypeAddress}},
    {"NtQueryBootOptions", {ParamTypeAddress, ParamTypeAddress}},
    {"NtQueryDebugFilterState", {ParamTypeFlag, ParamTypeFlag}},
    {"NtQueryDefaultLocale", {ParamTypeFlag, ParamTypeAddress}},
    {"NtQueryDefaultUILanguage", {ParamTypeAddress}},
    {"NtQueryDirectoryFile", {ParamTypeHandle, ParamTypeHandle, ParamTypeAddress, ParamTypeAddress, ParamTypeStatus, ParamTypeAddress, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeUnicodeStr, ParamTypeFlag}},
    {"NtQueryDirectoryObject", {ParamTypeHandle, ParamTypeAddress, ParamTypeBufferSize, ParamTypeFlag, ParamTypeFlag, ParamTypeAddress, ParamTypeRetLength}},
    {"NtQueryDriverEntryOrder", {ParamTypeAddress, ParamTypeAddress}},
    {"NtQueryEaFile", {ParamTypeHandle, ParamTypeStatus, ParamTypeAddress, ParamTypeFlag, ParamTypeFlag, ParamTypeAddress, ParamTypeFlag, ParamTypeAddress, ParamTypeFlag}},
    {"NtQueryFullAttributesFile", {ParamTypeObjectAttr, ParamTypeAddress}},
    {"NtQueryInformationAtom", {ParamTypeHandle, ParamTypeInfoClass, ParamTypeAddress, ParamTypeFlag, ParamTypeAddress}},
    {"NtQueryInformationEnlistment", {ParamTypeHandle, ParamTypeInfoClass, ParamTypeAddress, ParamTypeFlag, ParamTypeAddress}},
    {"NtQueryInformationFile", {ParamTypeHandle, ParamTypeStatus, ParamTypeAddress, ParamTypeFlag, ParamTypeInfoClass}},
    {"NtQueryInformationProcess", {ParamTypeHandle, ParamTypeInfoClass, ParamTypeAddress, ParamTypeBufferSize, ParamTypeRetLength}},
    {"NtQueryInformationResourceManager", {ParamTypeHandle, ParamTypeInfoClass, ParamTypeAddress, ParamTypeFlag, ParamTypeAddress}},
    {"NtQueryInformationThread", {ParamTypeHandle, ParamTypeInfoClass, ParamTypeAddress, ParamTypeBufferSize, ParamTypeRetLength}},
    {"NtQueryInformationToken", {ParamTypeToken, ParamTypeInfoClass, ParamTypeAddress, ParamTypeBufferSize, ParamTypeRetLength}},
    {"NtQueryInformationTransaction", {ParamTypeHandle, ParamTypeInfoClass, ParamTypeAddress, ParamTypeFlag, ParamTypeAddress}},
    {"NtQueryInformationTransactionManager", {ParamTypeHandle, ParamTypeFlag, ParamTypeAddress, ParamTypeFlag, ParamTypeAddress}},
    {"NtQueryInformationWorkerFactory", {ParamTypeHandle, ParamTypeFlag, ParamTypeAddress, ParamTypeFlag, ParamTypeAddress}},
    {"NtQueryInstallUILanguage", {ParamTypeAddress}},
    {"NtQueryIntervalProfile", {ParamTypeHandle, ParamTypeAddress}},
    {"NtQueryIoCompletion", {ParamTypeHandle, ParamTypeInfoClass, ParamTypeAddress, ParamTypeFlag, ParamTypeAddress}},
    {"NtQueryKey", {ParamTypeHandle, ParamTypeInfoClass, ParamTypeAddress, ParamTypeBufferSize, ParamTypeRetLength}},
    {"NtQueryLicenseValue", {ParamTypeUnicodeStr, ParamTypeAddress, ParamTypeAddress, ParamTypeFlag, ParamTypeAddress}},
    {"NtQueryMultipleValueKey", {ParamTypeHandle, ParamTypeAddress, ParamTypeFlag, ParamTypeAddress, ParamTypeAddress, ParamTypeAddress}},
    {"NtQueryMutant", {ParamTypeHandle, ParamTypeInfoClass, ParamTypeAddress, ParamTypeFlag, ParamTypeAddress}},
    {"NtQueryObject", {ParamTypeHandle, ParamTypeInfoClass, ParamTypeAddress, ParamTypeBufferSize, ParamTypeRetLength}},
    {"NtQueryOpenSubKeys", {ParamTypeObjectAttr, ParamTypeAddress}},
    {"NtQueryOpenSubKeysEx", {ParamTypeObjectAttr, ParamTypeFlag, ParamTypeAddress, ParamTypeAddress}},
    {"NtQueryPerformanceCounter", {ParamTypeAddress, ParamTypeAddress}},
    {"NtQuerySection", {ParamTypeHandle, ParamTypeInfoClass, ParamTypeAddress, ParamTypeFlag, ParamTypeAddress}},
    {"NtQuerySecurityAttributesToken", {ParamTypeHandle, ParamTypeAddress, ParamTypeFlag, ParamTypeAddress, ParamTypeFlag, ParamTypeAddress}},
    {"NtQuerySecurityObject", {ParamTypeHandle, ParamTypeFlag, ParamTypeAddress, ParamTypeFlag, ParamTypeAddress}},
    {"NtQuerySemaphore", {ParamTypeHandle, ParamTypeInfoClass, ParamTypeAddress, ParamTypeFlag, ParamTypeAddress}},
    {"NtQuerySymbolicLinkObject", {ParamTypeHandle, ParamTypeUnicodeStr, ParamTypeAddress}},
    {"NtQuerySystemEnvironmentValue", {ParamTypeUnicodeStr, ParamTypeAddress, ParamTypeFlag, ParamTypeAddress}},
    {"NtQuerySystemEnvironmentValueEx", {ParamTypeUnicodeStr, ParamTypeObjectAttr, ParamTypeAddress, ParamTypeAddress, ParamTypeAddress}},
    {"NtQuerySystemInformation", {ParamTypeInfoClass, ParamTypeAddress, ParamTypeBufferSize, ParamTypeRetLength}},
    {"NtQuerySystemInformationEx", {ParamTypeInfoClass, ParamTypeAddress, ParamTypeFlag, ParamTypeAddress, ParamTypeFlag, ParamTypeAddress}},
    {"NtQuerySystemTime", {ParamTypeAddress}},
    {"NtQueryTimer", {ParamTypeHandle, ParamTypeInfoClass, ParamTypeAddress, ParamTypeFlag, ParamTypeAddress}},
    {"NtQueryTimerResolution", {ParamTypeAddress, ParamTypeAddress, ParamTypeAddress}},
    {"NtQueryValueKey", {ParamTypeHandle, ParamTypeUnicodeStr, ParamTypeFlag, ParamTypeAddress, ParamTypeFlag, ParamTypeAddress}},
    {"NtQueryVirtualMemory", {ParamTypeHandle, ParamTypeAddress, ParamTypeInfoClass, ParamTypeAddress, ParamTypeBufferSize, ParamTypeRetLength}},
    {"NtQueryVolumeInformationFile", {ParamTypeHandle, ParamTypeStatus, ParamTypeAddress, ParamTypeFlag, ParamTypeInfoClass}},
    {"NtQueueApcThreadEx", {ParamTypeHandle, ParamTypeHandle, ParamTypeAddress, ParamTypeAddress, ParamTypeAddress, ParamTypeAddress}},
    {"NtRaiseException", {ParamTypeAddress, ParamTypeAddress, ParamTypeFlag}},
    {"NtReadFile", {ParamTypeHandle, ParamTypeHandle, ParamTypeAddress, ParamTypeAddress, ParamTypeStatus, ParamTypeAddress, ParamTypeFlag, ParamTypeAddress, ParamTypeFlag}},
    {"NtReadFileScatter", {ParamTypeHandle, ParamTypeHandle, ParamTypeAddress, ParamTypeAddress, ParamTypeStatus, ParamTypeAddress, ParamTypeFlag, ParamTypeAddress, ParamTypeFlag}},
    {"NtReadOnlyEnlistment", {ParamTypeHandle, ParamTypeAddress}},
    {"NtReadVirtualMemory", {ParamTypeHandle, ParamTypeAddress, ParamTypeAddress, ParamTypeFlag, ParamTypeAddress}},
    {"NtRecoverEnlistment", {ParamTypeHandle, ParamTypeAddress}},
    {"NtRecoverResourceManager", {ParamTypeHandle}},
    {"NtRecoverTransactionManager", {ParamTypeHandle}},
    {"NtRegisterProtocolAddressInformation", {ParamTypeHandle, ParamTypeFlag, ParamTypeFlag, ParamTypeAddress, ParamTypeFlag}},
    {"NtRemoveIoCompletion", {ParamTypeHandle, ParamTypeAddress, ParamTypeAddress, ParamTypeStatus, ParamTypeAddress}},
    {"NtRemoveIoCompletionEx", {ParamTypeHandle, ParamTypeAddress, ParamTypeAddress, ParamTypeAddress, ParamTypeAddress, ParamTypeFlag}},
    {"NtRemoveProcessDebug", {ParamTypeHandle, ParamTypeHandle}},
    {"NtRenameKey", {ParamTypeHandle, ParamTypeUnicodeStr}},
    {"NtRenameTransactionManager", {ParamTypeUnicodeStr, ParamTypeAddress}},
    {"NtReplaceKey", {ParamTypeObjectAttr, ParamTypeHandle, ParamTypeObjectAttr}},
    {"NtRequestDeviceWakeup", {ParamTypeHandle}},
    {"NtRequestWakeupLatency", {ParamTypeFlag}},
    {"NtResetEvent", {ParamTypeHandle, ParamTypeAddress}},
    {"NtResetWriteWatch", {ParamTypeHandle, ParamTypeAddress, ParamTypeFlag}},
    {"NtRestoreKey", {ParamTypeHandle, ParamTypeHandle, ParamTypeFlag}},
    {"NtResumeProcess", {ParamTypeHandle}},
    {"NtRollbackComplete", {ParamTypeHandle, ParamTypeAddress}},
    {"NtRollbackEnlistment", {ParamTypeHandle, ParamTypeAddress}},
    {"NtRollbackRegistryTransaction", {ParamTypeHandle, ParamTypeFlag}},
    {"NtRollbackTransaction", {ParamTypeHandle, ParamTypeFlag}},
    {"NtRollforwardTransactionManager", {ParamTypeHandle, ParamTypeAddress}},
    {"NtSaveKey", {ParamTypeHandle, ParamTypeHandle}},
    {"NtSaveKeyEx", {ParamTypeHandle, ParamTypeHandle, ParamTypeFlag}},
    {"NtSaveMergedKeys", {ParamTypeHandle, ParamTypeHandle, ParamTypeHandle}},
    {"NtSecureConnectPort", {ParamTypeAddress, ParamTypeUnicodeStr, ParamTypeAddress, ParamTypeAddress, ParamTypeAddress, ParamTypeAddress, ParamTypeAddress, ParamTypeAddress, ParamTypeAddress}},
    {"NtSerializeBoot", {0}},
    {"NtSetBootEntryOrder", {ParamTypeAddress, ParamTypeFlag}},
    {"NtSetBootOptions", {ParamTypeAddress, ParamTypeFlag}},
    {"NtSetCachedSigningLevel", {ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeHandle, ParamTypeHandle}},
    {"NtSetContextThread", {ParamTypeHandle, ParamTypeAddress}},
    {"NtSetDebugFilterState", {ParamTypeFlag, ParamTypeFlag, ParamTypeFlag}},
    {"NtSetDefaultHardErrorPort", {ParamTypeHandle}},
    {"NtSetDefaultLocale", {ParamTypeFlag, ParamTypeFlag}},
    {"NtSetDefaultUILanguage", {ParamTypeFlag}},
    {"NtSetDriverEntryOrder", {ParamTypeAddress, ParamTypeFlag}},
    {"NtSetEaFile", {ParamTypeHandle, ParamTypeStatus, ParamTypeAddress, ParamTypeFlag}},
    {"NtSetEvent", {ParamTypeHandle, ParamTypeAddress}},
    {"NtSetEventBoostPriority", {ParamTypeHandle}},
    {"NtSetHighEventPair", {ParamTypeHandle}},
    {"NtSetHighWaitLowEventPair", {ParamTypeHandle}},
    {"NtSetInformationDebugObject", {ParamTypeHandle, ParamTypeInfoClass, ParamTypeAddress, ParamTypeFlag, ParamTypeAddress}},
    {"NtSetInformationEnlistment", {ParamTypeHandle, ParamTypeInfoClass, ParamTypeAddress, ParamTypeFlag}},
    {"NtSetInformationFile", {ParamTypeHandle, ParamTypeStatus, ParamTypeAddress, ParamTypeFlag, ParamTypeInfoClass}},
    {"NtSetInformationJobObject", {ParamTypeHandle, ParamTypeInfoClass, ParamTypeAddress, ParamTypeBufferSize}},
    {"NtSetInformationKey", {ParamTypeHandle, ParamTypeInfoClass, ParamTypeAddress, ParamTypeBufferSize}},
    {"NtSetInformationObject", {ParamTypeHandle, ParamTypeInfoClass, ParamTypeAddress, ParamTypeBufferSize}},
    {"NtSetInformationProcess", {ParamTypeHandle, ParamTypeInfoClass, ParamTypeAddress, ParamTypeBufferSize}},
    {"NtSetInformationResourceManager", {ParamTypeHandle, ParamTypeInfoClass, ParamTypeAddress, ParamTypeFlag}},
    {"NtSetInformationSymbolicLink", {ParamTypeHandle, ParamTypeInfoClass, ParamTypeAddress, ParamTypeBufferSize}},
    {"NtSetInformationThread", {ParamTypeHandle, ParamTypeInfoClass, ParamTypeAddress, ParamTypeBufferSize}},
    {"NtSetInformationToken", {ParamTypeHandle, ParamTypeInfoClass, ParamTypeAddress, ParamTypeBufferSize}},
    {"NtSetInformationTransaction", {ParamTypeHandle, ParamTypeInfoClass, ParamTypeAddress, ParamTypeFlag}},
    {"NtSetInformationTransactionManager", {ParamTypeHandle, ParamTypeInfoClass, ParamTypeAddress, ParamTypeBufferSize}},
    {"NtSetInformationVirtualMemory", {ParamTypeHandle, ParamTypeInfoClass, ParamTypeFlag, ParamTypeAddress, ParamTypeAddress, ParamTypeFlag}},
    {"NtSetInformationWorkerFactory", {ParamTypeHandle, ParamTypeInfoClass, ParamTypeAddress, ParamTypeFlag}},
    {"NtSetIntervalProfile", {ParamTypeFlag, ParamTypeFlag}},
    {"NtSetIoCompletionEx", {ParamTypeHandle, ParamTypeHandle, ParamTypeAddress, ParamTypeAddress, ParamTypeStatus, ParamTypeFlag}},
    {"NtSetIRTimer", {ParamTypeHandle, ParamTypeAddress}},
    {"NtSetLowEventPair", {ParamTypeHandle}},
    {"NtSetLowWaitHighEventPair", {ParamTypeHandle}},
    {"NtSetQuotaInformationFile", {ParamTypeHandle, ParamTypeStatus, ParamTypeAddress, ParamTypeFlag}},
    {"NtSetSecurityObject", {ParamTypeHandle, ParamTypeFlag, ParamTypeAddress}},
    {"NtSetSystemEnvironmentValue", {ParamTypeUnicodeStr, ParamTypeUnicodeStr}},
    {"NtSetSystemEnvironmentValueEx", {ParamTypeUnicodeStr, ParamTypeObjectAttr, ParamTypeAddress, ParamTypeFlag, ParamTypeFlag}},
    {"NtSetSystemInformation", {ParamTypeInfoClass, ParamTypeAddress, ParamTypeBufferSize}},
    {"NtSetSystemTime", {ParamTypeAddress, ParamTypeAddress}},
    {"NtSetThreadExecutionState", {ParamTypeFlag, ParamTypeAddress}},
    {"NtSetTimer", {ParamTypeHandle, ParamTypeAddress, ParamTypeAddress, ParamTypeAddress, ParamTypeFlag, ParamTypeFlag, ParamTypeAddress}},
    {"NtSetTimerEx", {ParamTypeHandle, ParamTypeInfoClass, ParamTypeAddress, ParamTypeAddress}},
    {"NtSetTimerResolution", {ParamTypeFlag, ParamTypeFlag, ParamTypeAddress}},
    {"NtSetUuidSeed", {ParamTypeAddress}},
    {"NtSetValueKey", {ParamTypeHandle, ParamTypeUnicodeStr, ParamTypeFlag, ParamTypeFlag, ParamTypeAddress, ParamTypeFlag}},
    {"NtSetVolumeInformationFile", {ParamTypeHandle, ParamTypeStatus, ParamTypeAddress, ParamTypeFlag, ParamTypeFlag}},
    {"NtSetWnfProcessNotificationEvent", {ParamTypeHandle}},
    {"NtShutdownWorkerFactory", {ParamTypeHandle, ParamTypeAddress}},
    {"NtSignalAndWaitForSingleObject", {ParamTypeHandle, ParamTypeHandle, ParamTypeFlag, ParamTypeAddress}},
    {"NtSinglePhaseReject", {ParamTypeHandle, ParamTypeAddress}},
    {"NtStartProfile", {ParamTypeHandle}},
    {"NtStopProfile", {ParamTypeHandle}},
    {"NtSubscribeWnfStateChange", {ParamTypeAddress, ParamTypeFlag, ParamTypeFlag, ParamTypeAddress}},
    {"NtTestAlert", {0}},
    {"NtThawRegistry", {0}},
    {"NtThawTransactions", {0}},
    {"NtTraceControl", {ParamTypeFlag, ParamTypeAddress, ParamTypeFlag, ParamTypeAddress, ParamTypeFlag, ParamTypeAddress}},
    {"NtTraceEvent", {ParamTypeHandle, ParamTypeFlag, ParamTypeFlag, ParamTypeAddress}},
    {"NtTranslateFilePath", {ParamTypeAddress, ParamTypeFlag, ParamTypeAddress, ParamTypeAddress}},
    {"NtUnloadDriver", {ParamTypeUnicodeStr}},
    {"NtUnloadKey", {ParamTypeObjectAttr}},
    {"NtUnloadKey2", {ParamTypeObjectAttr, ParamTypeFlag}},
    {"NtUnloadKeyEx", {ParamTypeObjectAttr, ParamTypeHandle}},
    {"NtUnlockFile", {ParamTypeHandle, ParamTypeStatus, ParamTypeAddress, ParamTypeAddress, ParamTypeAddress}},
    {"NtUnlockVirtualMemory", {ParamTypeHandle, ParamTypeAddress, ParamTypeAddress, ParamTypeFlag}},
    {"NtUnmapViewOfSection", {ParamTypeHandle, ParamTypeAddress}},
    {"NtUnmapViewOfSectionEx", {ParamTypeHandle, ParamTypeAddress, ParamTypeFlag}},
    {"NtUnsubscribeWnfStateChange", {ParamTypeAddress}},
    {"NtUpdateWnfStateData", {ParamTypeAddress, ParamTypeAddress, ParamTypeFlag, ParamTypeFlag, ParamTypeAddress, ParamTypeFlag, ParamTypeFlag}},
    {"NtVdmControl", {ParamTypeFlag, ParamTypeAddress}},
    {"NtWaitForDebugEvent", {ParamTypeHandle, ParamTypeFlag, ParamTypeAddress, ParamTypeAddress}},
    {"NtWaitForMultipleObjects", {ParamTypeFlag, ParamTypeAddress, ParamTypeFlag, ParamTypeFlag, ParamTypeAddress}},
    {"NtWaitForMultipleObjects32", {ParamTypeFlag, ParamTypeAddress, ParamTypeFlag, ParamTypeFlag, ParamTypeAddress}},
    {"NtWaitForWorkViaWorkerFactory", {ParamTypeHandle, ParamTypeAddress}},
    {"NtWriteFile", {ParamTypeHandle, ParamTypeHandle, ParamTypeAddress, ParamTypeAddress, ParamTypeStatus, ParamTypeAddress, ParamTypeFlag, ParamTypeAddress, ParamTypeFlag}},
    {"NtWriteFileGather", {ParamTypeHandle, ParamTypeHandle, ParamTypeAddress, ParamTypeAddress, ParamTypeStatus, ParamTypeAddress, ParamTypeFlag, ParamTypeAddress, ParamTypeFlag}},
    {"NtWriteRequestData", {ParamTypeHandle, ParamTypeAddress, ParamTypeFlag, ParamTypeFlag, ParamTypeAddress, ParamTypeAddress}},
    {"NtWriteVirtualMemory", {ParamTypeHandle, ParamTypeAddress, ParamTypeAddress, ParamTypeFlag, ParamTypeAddress}},
    {"NtYieldExecution", {0}},

    {NULL, {0}}
};

// Win32k syscalls
const SYSCALL_PARAM_INFO KnownWin32kSyscalls[] = {
    {"NtGdiAddFontResourceW", {ParamTypeAddress, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeAddress}},
    {"NtGdiBitBlt", {ParamTypeGdiHandle, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeGdiHandle, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag}},
    {"NtGdiCombineRgn", {ParamTypeGdiHandle, ParamTypeGdiHandle, ParamTypeGdiHandle, ParamTypeFlag}},
    {"NtGdiCreateBitmap", {ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeAddress}},
    {"NtGdiCreateClientObj", {ParamTypeFlag}},
    {"NtGdiCreateCompatibleDC", {ParamTypeGdiHandle}},
    {"NtGdiCreateDIBBrush", {ParamTypeAddress, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeAddress}},
    {"NtGdiCreateDIBSection", {ParamTypeGdiHandle, ParamTypeHandle, ParamTypeFlag, ParamTypeAddress, ParamTypeAddress, ParamTypeFlag}},
    {"NtGdiCreateHalftonePalette", {ParamTypeGdiHandle}},
    {"NtGdiCreatePaletteInternal", {ParamTypeAddress, ParamTypeFlag}},
    {"NtGdiCreatePatternBrush", {ParamTypeHandle, ParamTypeFlag, ParamTypeFlag}},
    {"NtGdiCreatePen", {ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag}},
    {"NtGdiCreateRectRgn", {ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag}},
    {"NtGdiCreateRoundRectRgn", {ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag}},
    {"NtGdiCreateSolidBrush", {ParamTypeFlag, ParamTypeFlag}},
    {"NtGdiDdDDICloseAdapter", {ParamTypeAddress}},
    {"NtGdiDdDDICreateAllocation", {ParamTypeAddress}},
    {"NtGdiDdDDICreateContext", {ParamTypeAddress}},
    {"NtGdiDdDDICreateDevice", {ParamTypeAddress}},
    {"NtGdiDdDDICreateSynchronizationObject", {ParamTypeAddress}},
    {"NtGdiDeleteObjectApp", {ParamTypeGdiHandle}},
    {"NtGdiEnumFonts", {ParamTypeGdiHandle, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeAddress, ParamTypeAddress, ParamTypeAddress}},
    {"NtGdiExcludeUpdateRgn", {ParamTypeGdiHandle, ParamTypeWinHandle}},
    {"NtGdiExtTextOutW", {ParamTypeGdiHandle, ParamTypeFlag, ParamTypeFlag, ParamTypeAddress, ParamTypeAddress, ParamTypeUnicodeStr, ParamTypeFlag, ParamTypeFlag, ParamTypeAddress}},
    {"NtGdiFlattenPath", {ParamTypeGdiHandle}},
    {"NtGdiGetBitmapBits", {ParamTypeGdiHandle, ParamTypeFlag, ParamTypeAddress}},
    {"NtGdiGetBoundsRect", {ParamTypeGdiHandle, ParamTypeAddress, ParamTypeFlag}},
    {"NtGdiGetCharABCWidthsW", {ParamTypeGdiHandle, ParamTypeFlag, ParamTypeFlag, ParamTypeAddress, ParamTypeFlag, ParamTypeFlag}},
    {"NtGdiGetDCPoint", {ParamTypeGdiHandle, ParamTypeFlag, ParamTypeAddress}},
    {"NtGdiGetFontData", {ParamTypeGdiHandle, ParamTypeFlag, ParamTypeFlag, ParamTypeAddress, ParamTypeFlag}},
    {"NtGdiGetGlyphOutline", {ParamTypeGdiHandle, ParamTypeFlag, ParamTypeFlag, ParamTypeAddress, ParamTypeFlag, ParamTypeAddress, ParamTypeAddress, ParamTypeFlag}},
    {"NtGdiGetRandomRgn", {ParamTypeGdiHandle, ParamTypeGdiHandle, ParamTypeFlag}},
    {"NtGdiGetRasterizerCaps", {ParamTypeAddress, ParamTypeFlag}},
    {"NtGdiGetRegionData", {ParamTypeGdiHandle, ParamTypeFlag, ParamTypeAddress}},
    {"NtGdiGetTextExtentExW", {ParamTypeGdiHandle, ParamTypeAddress, ParamTypeFlag, ParamTypeFlag, ParamTypeAddress, ParamTypeAddress, ParamTypeAddress}},
    {"NtGdiGetTransform", {ParamTypeGdiHandle, ParamTypeFlag, ParamTypeAddress}},
    {"NtGdiHfontCreate", {ParamTypeAddress, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeAddress}},
    {"NtGdiInitSpool", {0}},
    {"NtGdiMakeFontDir", {ParamTypeFlag, ParamTypeAddress, ParamTypeFlag, ParamTypeAddress, ParamTypeFlag}},
    {"NtGdiMirrorWindowOrg", {ParamTypeGdiHandle}},
    {"NtGdiPolyPolyDraw", {ParamTypeGdiHandle, ParamTypeAddress, ParamTypeAddress, ParamTypeFlag, ParamTypeFlag}},
    {"NtGdiRemoveFontMemResourceEx", {ParamTypeHandle}},
    {"NtGdiResetDC", {ParamTypeGdiHandle, ParamTypeAddress, ParamTypeAddress, ParamTypeFlag, ParamTypeAddress}},
    {"NtGdiResizePalette", {ParamTypeGdiHandle, ParamTypeFlag}},
    {"NtGdiRoundRect", {ParamTypeGdiHandle, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag}},
    {"NtGdiSelectBrush", {ParamTypeGdiHandle, ParamTypeGdiHandle}},
    {"NtGdiSetBitmapBits", {ParamTypeGdiHandle, ParamTypeFlag, ParamTypeAddress}},
    {"NtGdiSetBkColor", {ParamTypeGdiHandle, ParamTypeFlag}},
    {"NtGdiSetBkMode", {ParamTypeGdiHandle, ParamTypeFlag}},
    {"NtGdiSetBrushOrg", {ParamTypeGdiHandle, ParamTypeFlag, ParamTypeFlag, ParamTypeAddress}},
    {"NtGdiSetMetaRgn", {ParamTypeGdiHandle}},
    {"NtGdiSetMiterLimit", {ParamTypeGdiHandle, ParamTypeFlag, ParamTypeAddress}},
    {"NtGdiSetPixelFormat", {ParamTypeGdiHandle, ParamTypeFlag}},
    {"NtGdiSetRectRgn", {ParamTypeGdiHandle, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag}},
    {"NtGdiSetTextColor", {ParamTypeGdiHandle, ParamTypeFlag}},
    {"NtGdiStretchBlt", {ParamTypeGdiHandle, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeGdiHandle, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag}},
    {"NtUserAddClipboardFormatListener", {ParamTypeWinHandle}},
    {"NtUserAppendMenu", {ParamTypeHandle, ParamTypeFlag, ParamTypeFlag, ParamTypeAddress}},
    {"NtUserAttachThreadInput", {ParamTypeFlag, ParamTypeFlag, ParamTypeFlag}},
    {"NtUserBeginPaint", {ParamTypeWinHandle, ParamTypeAddress}},
    {"NtUserBlockInput", {ParamTypeFlag}},
    {"NtUserBuildHwndList", {ParamTypeHandle, ParamTypeWinHandle, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeAddress, ParamTypeAddress}},
    {"NtUserBuildNameList", {ParamTypeHandle, ParamTypeFlag, ParamTypeAddress, ParamTypeAddress}},
    {"NtUserBuildPropList", {ParamTypeHandle, ParamTypeFlag, ParamTypeAddress, ParamTypeAddress}},
    {"NtUserCalcMenuBar", {ParamTypeWinHandle, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag}},
    {"NtUserCalculatePopupWindowPosition", {ParamTypeAddress, ParamTypeAddress, ParamTypeFlag, ParamTypeAddress, ParamTypeAddress}},
    {"NtUserCallWindowProc", {ParamTypeAddress, ParamTypeWinHandle, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag}},
    {"NtUserCanCurrentThreadChangeForeground", {0}},
    {"NtUserChangeDisplaySettings", {ParamTypeAddress, ParamTypeAddress, ParamTypeWinHandle, ParamTypeFlag, ParamTypeAddress}},
    {"NtUserCheckAccessForIntegrityLevel", {ParamTypeFlag, ParamTypeFlag, ParamTypeAddress}},
    {"NtUserCheckMenuItem", {ParamTypeHandle, ParamTypeFlag, ParamTypeFlag}},
    {"NtUserCheckProcessForClipboardAccess", {ParamTypeFlag, ParamTypeAddress}},
    {"NtUserChildWindowFromPoint", {ParamTypeWinHandle, ParamTypeFlag, ParamTypeFlag}},
    {"NtUserChildWindowFromPointEx", {ParamTypeWinHandle, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag}},
    {"NtUserClipCursor", {ParamTypeAddress}},
    {"NtUserCloseClipboard", {0}},
    {"NtUserCloseDesktop", {ParamTypeHandle}},
    {"NtUserCloseWindowStation", {ParamTypeHandle}},
    {"NtUserConsoleControl", {ParamTypeFlag, ParamTypeAddress, ParamTypeFlag}},
    {"NtUserCopyAcceleratorTable", {ParamTypeHandle, ParamTypeAddress, ParamTypeFlag}},
    {"NtUserCreateAcceleratorTable", {ParamTypeAddress, ParamTypeFlag}},
    {"NtUserCreateCaret", {ParamTypeWinHandle, ParamTypeHandle, ParamTypeFlag, ParamTypeFlag}},
    {"NtUserCreateCursor", {ParamTypeHandle, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeAddress, ParamTypeAddress}},
    {"NtUserCreateDCompositionHwndTarget", {ParamTypeWinHandle, ParamTypeFlag, ParamTypeFlag}},
    {"NtUserCreateDesktop", {ParamTypeUnicodeStr, ParamTypeUnicodeStr, ParamTypeAddress, ParamTypeFlag, ParamTypeAccess, ParamTypeFlag}},
    {"NtUserCreateIconIndirect", {ParamTypeAddress}},
    {"NtUserCreateMenu", {0}},
    {"NtUserCreateWindowEx", {ParamTypeFlag, ParamTypeUnicodeStr, ParamTypeUnicodeStr, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeWinHandle, ParamTypeHandle, ParamTypeHandle, ParamTypeAddress, ParamTypeFlag}},
    {"NtUserCreateWindowStation", {ParamTypeObjectAttr, ParamTypeAccess, ParamTypeHandle, ParamTypeAddress, ParamTypeAddress, ParamTypeAddress, ParamTypeAddress, ParamTypeFlag}},
    {"NtUserDefWindowProc", {ParamTypeWinHandle, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag}},
    {"NtUserDeleteMenu", {ParamTypeHandle, ParamTypeFlag, ParamTypeFlag}},
    {"NtUserDestroyAcceleratorTable", {ParamTypeHandle}},
    {"NtUserDestroyCursor", {ParamTypeHandle, ParamTypeFlag}},
    {"NtUserDestroyMenu", {ParamTypeHandle}},
    {"NtUserDestroyWindow", {ParamTypeWinHandle}},
    {"NtUserDisableProcessWindowsGhosting", {0}},
    {"NtUserDragDetect", {ParamTypeWinHandle, ParamTypeFlag, ParamTypeFlag}},
    {"NtUserDragObject", {ParamTypeWinHandle, ParamTypeWinHandle, ParamTypeFlag, ParamTypeAddress, ParamTypeHandle}},
    {"NtUserDrawAnimatedRects", {ParamTypeWinHandle, ParamTypeFlag, ParamTypeAddress, ParamTypeAddress}},
    {"NtUserEmptyClipboard", {0}},
    {"NtUserEnableSoftwareCursor", {ParamTypeFlag, ParamTypeFlag}},
    {"NtUserEndMenu", {0}},
    {"NtUserEndPaint", {ParamTypeWinHandle, ParamTypeAddress}},
    {"NtUserEnumDisplayDevices", {ParamTypeUnicodeStr, ParamTypeFlag, ParamTypeAddress, ParamTypeFlag}},
    {"NtUserEnumDisplayMonitors", {ParamTypeGdiHandle, ParamTypeAddress, ParamTypeAddress, ParamTypeAddress}},
    {"NtUserEnumDisplaySettings", {ParamTypeUnicodeStr, ParamTypeFlag, ParamTypeAddress, ParamTypeFlag}},
    {"NtUserFindWindowEx", {ParamTypeWinHandle, ParamTypeWinHandle, ParamTypeUnicodeStr, ParamTypeUnicodeStr, ParamTypeFlag}},
    {"NtUserFlashWindowEx", {ParamTypeAddress}},
    {"NtUserGetAncestor", {ParamTypeWinHandle, ParamTypeFlag}},
    {"NtUserGetAsyncKeyState", {ParamTypeFlag}},
    {"NtUserGetCaretBlinkTime", {0}},
    {"NtUserGetCaretPos", {ParamTypeAddress}},
    {"NtUserGetClassName", {ParamTypeWinHandle, ParamTypeFlag, ParamTypeUnicodeStr}},
    {"NtUserGetClipboardData", {ParamTypeFlag, ParamTypeAddress}},
    {"NtUserGetClipboardFormatName", {ParamTypeFlag, ParamTypeAddress, ParamTypeFlag}},
    {"NtUserGetClipCursor", {ParamTypeAddress}},
    {"NtUserGetComboBoxInfo", {ParamTypeWinHandle, ParamTypeAddress}},
    {"NtUserGetCurrentInputMessageSource", {ParamTypeAddress}},
    {"NtUserGetCursorInfo", {ParamTypeAddress}},
    {"NtUserGetCursorPos", {ParamTypeAddress}},
    {"NtUserGetDC", {ParamTypeWinHandle}},
    {"NtUserGetDCEx", {ParamTypeWinHandle, ParamTypeHandle, ParamTypeFlag}},
    {"NtUserGetDisplayAutoRotationPreferences", {ParamTypeAddress}},
    {"NtUserGetDoubleClickTime", {0}},
    {"NtUserGetForegroundWindow", {0}},
    {"NtUserGetGuiResources", {ParamTypeHandle, ParamTypeFlag}},
    {"NtUserGetGUIThreadInfo", {ParamTypeFlag, ParamTypeAddress}},
    {"NtUserGetIconInfo", {ParamTypeHandle, ParamTypeAddress, ParamTypeUnicodeStr, ParamTypeUnicodeStr, ParamTypeAddress, ParamTypeFlag}},
    {"NtUserGetIconSize", {ParamTypeHandle, ParamTypeFlag, ParamTypeAddress, ParamTypeAddress}},
    {"NtUserGetKeyState", {ParamTypeFlag}},
    {"NtUserGetLayeredWindowAttributes", {ParamTypeWinHandle, ParamTypeAddress, ParamTypeAddress, ParamTypeAddress}},
    {"NtUserGetListBoxInfo", {ParamTypeWinHandle}},
    {"NtUserGetMenuBarInfo", {ParamTypeWinHandle, ParamTypeFlag, ParamTypeFlag, ParamTypeAddress}},
    {"NtUserGetMenuItemRect", {ParamTypeWinHandle, ParamTypeHandle, ParamTypeFlag, ParamTypeAddress}},
    {"NtUserGetMouseMovePointsEx", {ParamTypeFlag, ParamTypeAddress, ParamTypeAddress, ParamTypeFlag, ParamTypeFlag}},
    {"NtUserGetObjectInformation", {ParamTypeHandle, ParamTypeFlag, ParamTypeAddress, ParamTypeFlag, ParamTypeAddress}},
    {"NtUserGetProcessWindowStation", {0}},
    {"NtUserGetRawInputData", {ParamTypeHandle, ParamTypeFlag, ParamTypeAddress, ParamTypeAddress, ParamTypeFlag}},
    {"NtUserGetRawInputDeviceList", {ParamTypeAddress, ParamTypeAddress, ParamTypeFlag}},
    {"NtUserGetRegisteredRawInputDevices", {ParamTypeAddress, ParamTypeAddress, ParamTypeFlag}},
    {"NtUserGetScrollBarInfo", {ParamTypeWinHandle, ParamTypeFlag, ParamTypeAddress}},
    {"NtUserGetSendMessageReceiver", {ParamTypeHandle}},
    {"NtUserGetSysColor", {ParamTypeFlag}},
    {"NtUserGetSystemMenu", {ParamTypeWinHandle, ParamTypeFlag}},
    {"NtUserGetSystemMetrics", {ParamTypeFlag}},
    {"NtUserGetThreadDesktop", {ParamTypeFlag}},
    {"NtUserGetThreadState", {ParamTypeFlag}},
    {"NtUserGetTitleBarInfo", {ParamTypeWinHandle, ParamTypeAddress}},
    {"NtUserGetWindowDC", {ParamTypeWinHandle}},
    {"NtUserGetWindowLong", {ParamTypeWinHandle, ParamTypeFlag, ParamTypeFlag}},
    {"NtUserGetWindowPlacement", {ParamTypeWinHandle, ParamTypeAddress}},
    {"NtUserGhostWindowFromHungWindow", {ParamTypeWinHandle}},
    {"NtUserHideCaret", {ParamTypeWinHandle}},
    {"NtUserHiliteMenuItem", {ParamTypeWinHandle, ParamTypeHandle, ParamTypeFlag, ParamTypeFlag}},
    {"NtUserHungWindowFromGhostWindow", {ParamTypeWinHandle}},
    {"NtUserInternalGetWindowIcon", {ParamTypeWinHandle, ParamTypeFlag}},
    {"NtUserInternalGetWindowText", {ParamTypeWinHandle, ParamTypeAddress, ParamTypeFlag}},
    {"NtUserInvalidateRect", {ParamTypeWinHandle, ParamTypeAddress, ParamTypeFlag}},
    {"NtUserInvalidateRgn", {ParamTypeWinHandle, ParamTypeHandle, ParamTypeFlag}},
    {"NtUserIsTouchWindow", {ParamTypeWinHandle, ParamTypeAddress}},
    {"NtUserKillTimer", {ParamTypeWinHandle, ParamTypeAddress}},
    {"NtUserLockWorkStation", {0}},
    {"NtUserLogicalToPhysicalPoint", {ParamTypeWinHandle, ParamTypeAddress}},
    {"NtUserMapVirtualKeyEx", {ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeHandle}},
    {"NtUserMenuItemFromPoint", {ParamTypeWinHandle, ParamTypeHandle, ParamTypeFlag, ParamTypeFlag}},
    {"NtUserModifyUserStartupInfoFlags", {ParamTypeFlag, ParamTypeFlag}},
    {"NtUserMonitorFromWindow", {ParamTypeWinHandle, ParamTypeFlag}},
    {"NtUserMoveWindow", {ParamTypeWinHandle, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag}},
    {"NtUserOpenClipboard", {ParamTypeWinHandle, ParamTypeFlag}},
    {"NtUserOpenDesktop", {ParamTypeObjectAttr, ParamTypeFlag, ParamTypeAccess}},
    {"NtUserOpenInputDesktop", {ParamTypeFlag, ParamTypeFlag, ParamTypeAccess}},
    {"NtUserOpenProcessForOptionSet", {ParamTypeFlag, ParamTypeFlag, ParamTypeFlag}},
    {"NtUserOpenWindowStation", {ParamTypeObjectAttr, ParamTypeAccess}},
    {"NtUserPhysicalToLogicalPoint", {ParamTypeWinHandle, ParamTypeAddress}},
    {"NtUserPrintWindow", {ParamTypeWinHandle, ParamTypeGdiHandle, ParamTypeFlag}},
    {"NtUserQueryInformationThread", {ParamTypeHandle, ParamTypeInfoClass, ParamTypeAddress, ParamTypeAddress}},
    {"NtUserQueryWindow", {ParamTypeWinHandle, ParamTypeFlag}},
    {"NtUserRaiseLowerShellWindow", {ParamTypeWinHandle, ParamTypeFlag}},
    {"NtUserRealChildWindowFromPoint", {ParamTypeWinHandle, ParamTypeFlag, ParamTypeFlag}},
    {"NtUserRedrawWindow", {ParamTypeWinHandle, ParamTypeAddress, ParamTypeHandle, ParamTypeFlag}},
    {"NtUserRegisterClassExWOW", {ParamTypeAddress, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeHandle, ParamTypeFlag}},
    {"NtUserRegisterHotKey", {ParamTypeWinHandle, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag}},
    {"NtUserRegisterRawInputDevices", {ParamTypeAddress, ParamTypeFlag, ParamTypeFlag}},
    {"NtUserReleaseDC", {ParamTypeWinHandle, ParamTypeGdiHandle}},
    {"NtUserRemoveClipboardFormatListener", {ParamTypeWinHandle}},
    {"NtUserRemoveMenu", {ParamTypeHandle, ParamTypeFlag, ParamTypeFlag}},
    {"NtUserSendEventMessage", {ParamTypeWinHandle, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag}},
    {"NtUserSendInput", {ParamTypeFlag, ParamTypeAddress, ParamTypeFlag}},
    {"NtUserSetActiveWindow", {ParamTypeWinHandle}},
    {"NtUserSetAdditionalForegroundBoostProcesses", {ParamTypeWinHandle}},
    {"NtUserSetAdditionalPowerThrottlingProcess", {ParamTypeWinHandle}},
    {"NtUserSetCapture", {ParamTypeWinHandle}},
    {"NtUserSetChildWindowNoActivate", {ParamTypeWinHandle}},
    {"NtUserSetClassWord", {ParamTypeWinHandle, ParamTypeFlag, ParamTypeFlag}},
    {"NtUserSetClipboardData", {ParamTypeFlag, ParamTypeHandle, ParamTypeFlag}},
    {"NtUserSetCursorPos", {ParamTypeFlag, ParamTypeFlag}},
    {"NtUserSetFocus", {ParamTypeWinHandle}},
    {"NtUserSetForegroundWindowForApplication", {ParamTypeWinHandle}},
    {"NtUserSetInformationThread", {ParamTypeHandle, ParamTypeInfoClass, ParamTypeAddress, ParamTypeFlag}},
    {"NtUserSetLayeredWindowAttributes", {ParamTypeWinHandle, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag}},
    {"NtUserSetMenu", {ParamTypeWinHandle, ParamTypeHandle, ParamTypeFlag}},
    {"NtUserSetMessageExtraInfo", {ParamTypeAddress}},
    {"NtUserSetProcessRestrictionExemption", {ParamTypeFlag}},
    {"NtUserSetProcessWindowStation", {ParamTypeHandle}},
    {"NtUserSetThreadDesktop", {ParamTypeHandle}},
    {"NtUserSetTimer", {ParamTypeWinHandle, ParamTypeAddress, ParamTypeFlag, ParamTypeAddress, ParamTypeFlag}},
    {"NtUserSetWindowDisplayAffinity", {ParamTypeWinHandle, ParamTypeFlag}},
    {"NtUserSetWindowLong", {ParamTypeWinHandle, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag}},
    {"NtUserSetWindowPlacement", {ParamTypeWinHandle, ParamTypeAddress}},
    {"NtUserSetWindowPos", {ParamTypeWinHandle, ParamTypeWinHandle, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag}},
    {"NtUserSetWindowRgn", {ParamTypeWinHandle, ParamTypeHandle, ParamTypeFlag}},
    {"NtUserSetWindowStationUser", {ParamTypeHandle, ParamTypeAddress, ParamTypeAddress, ParamTypeFlag}},
    {"NtUserSetWindowWord", {ParamTypeWinHandle, ParamTypeFlag, ParamTypeFlag}},
    {"NtUserShellForegroundBoostProcess", {ParamTypeHandle, ParamTypeWinHandle}},
    {"NtUserShowCaret", {ParamTypeWinHandle}},
    {"NtUserShowCursor", {ParamTypeFlag}},
    {"NtUserShowWindow", {ParamTypeWinHandle, ParamTypeFlag}},
    {"NtUserShowWindowAsync", {ParamTypeWinHandle, ParamTypeFlag}},
    {"NtUserShutdownBlockReasonQuery", {ParamTypeWinHandle, ParamTypeAddress, ParamTypeAddress}},
    {"NtUserShutdownReasonDestroy", {ParamTypeWinHandle}},
    {"NtUserSwitchDesktop", {ParamTypeHandle, ParamTypeFlag, ParamTypeFlag}},
    {"NtUserTestForInteractiveUser", {ParamTypeAddress}},
    {"NtUserThunkedMenuInfo", {ParamTypeHandle, ParamTypeAddress}},
    {"NtUserThunkedMenuItemInfo", {ParamTypeHandle, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeAddress, ParamTypeFlag}},
    {"NtUserToUnicodeEx", {ParamTypeFlag, ParamTypeFlag, ParamTypeAddress, ParamTypeAddress, ParamTypeFlag, ParamTypeFlag, ParamTypeHandle}},
    {"NtUserTrackMouseEvent", {ParamTypeAddress}},
    {"NtUserTrackPopupMenu", {ParamTypeHandle, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeWinHandle, ParamTypeAddress, ParamTypeFlag}},
    {"NtUserTrackPopupMenuEx", {ParamTypeHandle, ParamTypeFlag, ParamTypeFlag, ParamTypeFlag, ParamTypeWinHandle, ParamTypeAddress}},
    {"NtUserUnhookWinEvent", {ParamTypeHandle}},
    {"NtUserUnregisterHotKey", {ParamTypeWinHandle, ParamTypeFlag}},
    {"NtUserUpdateWindow", {ParamTypeWinHandle}},
    {"NtUserUserHandleGrantAccess", {ParamTypeHandle, ParamTypeHandle, ParamTypeFlag}},
    {"NtUserValidateRect", {ParamTypeWinHandle, ParamTypeAddress}},
    {"NtUserVkKeyScanEx", {ParamTypeFlag, ParamTypeFlag, ParamTypeHandle}},
    {"NtUserWindowFromDC", {ParamTypeGdiHandle}},
    {"NtUserWindowFromPhysicalPoint", {ParamTypeFlag, ParamTypeFlag}},
    {"NtUserWindowFromPoint", {ParamTypeFlag, ParamTypeFlag}},

    // Terminator
    {NULL, {0}}
};

#define KNOWN_NT_SYSCALLS_COUNT     (sizeof(KnownNtSyscalls) / sizeof(KnownNtSyscalls[0]) - 1)
#define KNOWN_WIN32K_SYSCALLS_COUNT (sizeof(KnownWin32kSyscalls) / sizeof(KnownWin32kSyscalls[0]) - 1)
