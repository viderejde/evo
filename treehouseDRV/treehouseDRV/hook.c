#include "hook.h" 
#include "mem.h"
#include <stdio.h>
#include <string.h>

bool callKernelFunc(void* kernelFuncAddress)
{
    if (!kernelFuncAddress)
        return false;

    PVOID* function = (PVOID*)(getSystemModuleExport("\\SystemRoot\\System32\\drivers\\dxgkrnl.sys", "NtDxgkGetTrackedWorkloadStatistics"));

    if (!function)
        return false;

    BYTE orig[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    BYTE shellcode[] = { 0x48, 0xB8 };
    BYTE shellcode_end[] = { 0xFF, 0xE0 };

    RtlSecureZeroMemory(&orig, sizeof(orig));
    memcpy((PVOID)((ULONG_PTR)orig), &shellcode, sizeof(shellcode));
    uintptr_t hookAddress = (uintptr_t)(kernelFuncAddress);

    memcpy((PVOID)((ULONG_PTR)orig + sizeof(shellcode)), &hookAddress, sizeof(void*));
    memcpy((PVOID)((ULONG_PTR)orig + sizeof(shellcode) + sizeof(void*)), &shellcode_end, sizeof(shellcode_end));

    writeToReadOnlyMemory(function, &orig, sizeof(orig));

    msg("hooked");
    return true;
}

NTSTATUS hookHandler(PVOID calledParam) {
    SEQUOIA_MESSAGE* instructions = (SEQUOIA_MESSAGE*)calledParam;

    if (instructions->requestPID != FALSE) {

        ANSI_STRING AS;
        RtlInitAnsiString(&AS, instructions->moduleName);
        PCHAR gameName = AS.Buffer;

        getEPROCESS(gameName);
        instructions->returnPID = gamePID;
    }
    return STATUS_SUCCESS;
}