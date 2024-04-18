#pragma warning (disable : 4100 4047 4024)

#include "hook.h"
#include "definitions.h"
#include "mem.h"
#include <ntifs.h>


NTSTATUS UnloadDriver(PDRIVER_OBJECT pDriverObject)
{
    msg("unloaded %s", pDriverObject->DriverName);
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
    UNREFERENCED_PARAMETER(pRegistryPath);
    pDriverObject->DriverUnload = UnloadDriver;
   
    msg("loaded %s", pDriverObject->DriverName);

    callKernelFunc(&hookHandler);
    return STATUS_SUCCESS;
}

