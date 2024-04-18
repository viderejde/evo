#pragma once

#pragma warning (disable : 4100 4047 4024 4267)

#include "definitions.h"
#include <stdbool.h>

#define IMAGE_FILE_NAME 0x5A8
#define ACTIVE_PROCESS_LINKS 0x448
#define PROCESS_ID 0x440

void getEPROCESS(PCHAR gameName) { // go through process list

    PEPROCESS sequoia_PsInitialSystemProcess = PsInitialSystemProcess;
    PEPROCESS currentEntry = sequoia_PsInitialSystemProcess;
    do
    {
        const UINT_PTR _currentEntry = (UINT_PTR)currentEntry;
        if (!_currentEntry)
            break;

        if (strcmp((PCHAR)(_currentEntry + IMAGE_FILE_NAME), gameName) == 0) // in correct EPROCESS STRUCT
        {
            gamePID = *(PVOID*)((UINT_PTR)currentEntry + 0x440);
            msg("%s PID is: %lu", gameName, gamePID);
            return;
        }

        PLIST_ENTRY list = (PLIST_ENTRY)(_currentEntry + ACTIVE_PROCESS_LINKS);
        currentEntry = (PEPROCESS)((UINT_PTR)list->Flink - ACTIVE_PROCESS_LINKS);

    } while (currentEntry != sequoia_PsInitialSystemProcess);
}

PVOID getSystemModuleBase(const char* moduleName) { // get driver with chosen func
    ULONG bytes = 0;
    NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, NULL, bytes, &bytes);

    if (!bytes)
        return NULL;

    PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, 0x74726565); // check bytes later

    status = ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);

    if (!NT_SUCCESS(status))
        return NULL;

    PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
    PVOID moduleBase = 0, moduleSize = 0;

    for (ULONG i = 0; i < modules->NumberOfModules; i++) {
        if (strcmp((char*)module[i].FullPathName, moduleName) == 0) {
            moduleBase = module[i].ImageBase;
            moduleSize = (PVOID)module[i].ImageSize;
            break;
        }
    }

    if (modules)
        ExFreePoolWithTag(modules, NULL);

    if (moduleBase <= NULL)
        return NULL;

    return moduleBase;
}

PVOID getSystemModuleExport(const char* moduleName, LPCSTR routineName) { // call to find driver then get func address
    PVOID lpModule = getSystemModuleBase(moduleName);
    if (!lpModule)
        return NULL;

    return RtlFindExportedRoutineByName(lpModule, routineName);
}

bool writeMemory(void* address, void* buffer, size_t size) {
    if (!RtlCopyMemory(address, buffer, size)) {
        return false;
    }
    else {
        return true;
    }
}

bool writeToReadOnlyMemory(void* address, void* buffer, size_t size) {
    PMDL Mdl = IoAllocateMdl(address, size, FALSE, FALSE, NULL);

    if (!Mdl)
        return false;

    MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);
    PVOID Mapping = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
    MmProtectMdlSystemAddress(Mdl, PAGE_READWRITE);

    writeMemory(Mapping, buffer, size);

    MmUnmapLockedPages(Mapping, Mdl);
    MmUnlockPages(Mdl);
    IoFreeMdl(Mdl);

    return true;
}

