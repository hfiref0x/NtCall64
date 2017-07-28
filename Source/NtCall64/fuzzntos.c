/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016 - 2017
*
*  TITLE:       FUZZNTOS.C
*
*  VERSION:     1.20
*
*  DATE:        28 July 2017
*
*  Service table fuzzing routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "main.h"
#include "fuzz.h"

const BYTE  KiSystemServiceStartPattern[] = { 0x45, 0x33, 0xC9, 0x44, 0x8B, 0x05 };

#define MAX_FUZZTHREADS     32

RAW_SERVICE_TABLE	g_Sdt;
HANDLE              g_FuzzingThreads[MAX_FUZZTHREADS];
BADCALLS            g_NtOsSyscallBlacklist;

/*
* find_kiservicetable
*
* Purpose:
*
* Locate KiServiceTable in mapped ntoskrnl copy.
*
*/
BOOL find_kiservicetable(
    ULONG_PTR           MappedImageBase,
    PRAW_SERVICE_TABLE  ServiceTable
)
{
    ULONG_PTR             SectionPtr = 0;
    IMAGE_NT_HEADERS     *NtHeaders = RtlImageNtHeader((PVOID)MappedImageBase);
    IMAGE_SECTION_HEADER *SectionTableEntry;
    ULONG                 c, p, SectionSize = 0, SectionVA = 0;

    SectionTableEntry = (PIMAGE_SECTION_HEADER)((PCHAR)NtHeaders +
        sizeof(ULONG) +
        sizeof(IMAGE_FILE_HEADER) +
        NtHeaders->FileHeader.SizeOfOptionalHeader);

    c = NtHeaders->FileHeader.NumberOfSections;
    while (c > 0) {
        if (*(PULONG)SectionTableEntry->Name == 'EGAP')
            if ((SectionTableEntry->Name[4] == 'L') &&
                (SectionTableEntry->Name[5] == 'K') &&
                (SectionTableEntry->Name[6] == 0))

            {
                SectionVA = SectionTableEntry->VirtualAddress;
                SectionPtr = ((ULONG_PTR)MappedImageBase + SectionVA);
                SectionSize = SectionTableEntry->Misc.VirtualSize;
                break;
            }
        c -= 1;
        SectionTableEntry += 1;
    }

    if ((SectionPtr == 0) || (SectionSize == 0) || (SectionVA == 0)) {
        return FALSE;
    }

    p = 0;
    for (c = 0; c < (SectionSize - sizeof(KiSystemServiceStartPattern)); c++)
        if (RtlCompareMemory(
            (PVOID)(SectionPtr + c),
            KiSystemServiceStartPattern,
            sizeof(KiSystemServiceStartPattern)) == sizeof(KiSystemServiceStartPattern))
        {
            p = SectionVA + c;
            break;
        }

    if (p == 0)
        return FALSE;

    p += 3;
    c = *((PULONG)(MappedImageBase + p + 3)) + 7 + p;
    ServiceTable->CountOfEntries = *((PULONG)(MappedImageBase + c));
    p += 7;
    c = *((PULONG)(MappedImageBase + p + 3)) + 7 + p;
    ServiceTable->StackArgumentTable = (PBYTE)MappedImageBase + c;
    p += 7;
    c = *((PULONG)(MappedImageBase + p + 3)) + 7 + p;
    ServiceTable->ServiceTable = (LPVOID *)(MappedImageBase + c);

    return TRUE;
}

/*
* PELoaderGetProcNameBySDTIndex
*
* Purpose:
*
* Return name of service from ntdll by given syscall id.
*
*/
PCHAR PELoaderGetProcNameBySDTIndex(
    ULONG_PTR	MappedImageBase,
    ULONG		SDTIndex
)
{

    PIMAGE_NT_HEADERS			nthdr = RtlImageNtHeader((PVOID)MappedImageBase);
    PIMAGE_EXPORT_DIRECTORY		ExportDirectory;

    ULONG_PTR	ExportDirectoryOffset;
    PULONG		NameTableBase;
    PUSHORT		NameOrdinalTableBase;
    PULONG		Addr;
    PBYTE		pfn;
    ULONG		c;

    ExportDirectoryOffset =
        nthdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    if (ExportDirectoryOffset == 0)
        return NULL;

    ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(MappedImageBase + ExportDirectoryOffset);
    NameTableBase = (PULONG)(MappedImageBase + (ULONG)ExportDirectory->AddressOfNames);
    NameOrdinalTableBase = (PUSHORT)(MappedImageBase + (ULONG)ExportDirectory->AddressOfNameOrdinals);
    Addr = (PULONG)(MappedImageBase + (ULONG)ExportDirectory->AddressOfFunctions);

    for (c = 0; c < ExportDirectory->NumberOfNames; c++) {
        pfn = (PBYTE)(MappedImageBase + Addr[NameOrdinalTableBase[c]]);
        if (*((PULONG)pfn) == 0xb8d18b4c)
            if (*((PULONG)(pfn + 4)) == SDTIndex)
                return (PCHAR)(MappedImageBase + NameTableBase[c]);
    }

    return NULL;
}

/*
* fuzzntos_proc
*
* Purpose:
*
* Handler for fuzzing thread.
*
*/
DWORD WINAPI fuzzntos_proc(
    PVOID Parameter
)
{
    BOOL   bSkip = FALSE;
    ULONG  c, r;
    PCHAR  Name1;
    CHAR   textbuf[512];
    ULONG_PTR NtdllImage;

    NtdllImage = (ULONG_PTR)GetModuleHandle(TEXT("ntdll.dll"));
    if (NtdllImage == 0)
        return 0;

    for (c = 0; c < g_Sdt.CountOfEntries; c++) {
        Name1 = (PCHAR)PELoaderGetProcNameBySDTIndex(NtdllImage, c);

        _strcpy_a(textbuf, "tid #");
        ultostr_a((ULONG)(ULONG_PTR)Parameter, _strend_a(textbuf));

        _strcat_a(textbuf, "\targs(stack): ");
        ultostr_a(g_Sdt.StackArgumentTable[c] / 4, _strend_a(textbuf));

        _strcat_a(textbuf, "\tsid ");
        ultostr_a(c, _strend_a(textbuf));
        _strcat_a(textbuf, "\tname:");
        if (Name1 != NULL) {
            _strcat_a(textbuf, Name1);
        }
        else {
            _strcat_a(textbuf, "#noname#");
        }

        bSkip = SyscallBlacklisted(Name1, &g_NtOsSyscallBlacklist);
        if (bSkip) {
            _strcat_a(textbuf, " ******* found in blacklist, skip");
        }
        _strcat_a(textbuf, "\r\n");
        WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), textbuf, (DWORD)_strlen_a(textbuf), &r, NULL);

        if (bSkip)
            continue;

        for (r = 0; r < 64 * 1024; r++)
            gofuzz(c, g_Sdt.StackArgumentTable[c]);
    }

    return 0;
}

/*
* fuzz_ntos
*
* Purpose:
*
* Launch ntos service table fuzzing using MAX_FUZZTHREADS number of threads.
*
*/
void fuzz_ntos()
{
    BOOL        bCond = FALSE;
    WCHAR       szBuffer[MAX_PATH * 2];
    ULONG_PTR   KernelImage = 0;
    ULONG       c, r;

    do {
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        if (!GetSystemDirectory(szBuffer, MAX_PATH))
            break;
        _strcat(szBuffer, TEXT("\\ntoskrnl.exe"));
        KernelImage = (ULONG_PTR)LoadLibraryEx(szBuffer, NULL, 0);
        if (KernelImage == 0)
            break;

        RtlSecureZeroMemory(&g_NtOsSyscallBlacklist, sizeof(g_NtOsSyscallBlacklist));
        ReadBlacklistCfg(&g_NtOsSyscallBlacklist, CFG_FILE, "ntos");

        if (!find_kiservicetable(KernelImage, &g_Sdt))
            break;

        RtlSecureZeroMemory(g_FuzzingThreads, sizeof(g_FuzzingThreads));

        force_priv();

        for (c = 0; c < MAX_FUZZTHREADS; c++) {
            g_FuzzingThreads[c] = CreateThread(NULL, 0, fuzzntos_proc, (LPVOID)(ULONG_PTR)c, 0, &r);
        }

        WaitForMultipleObjects(MAX_FUZZTHREADS, g_FuzzingThreads, TRUE, INFINITE);

        for (c = 0; c < MAX_FUZZTHREADS; c++) {
            CloseHandle(g_FuzzingThreads[c]);
        }

    } while (bCond);

    if (KernelImage != 0) FreeLibrary((HMODULE)KernelImage);
    OutputConsoleMessage("Ntoskrnl services fuzzing complete.\r\n");
}
