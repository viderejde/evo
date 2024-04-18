#pragma once
#include "mem.h"

typedef struct _SEQUOIA_MESSAGE
{
	BOOLEAN requestPID;
	const char* moduleName;
	ULONG returnPID;
}SEQUOIA_MESSAGE;

bool callKernelFunc(void* kernelFunctionAddress);
NTSTATUS hookHandler(PVOID calledParam);