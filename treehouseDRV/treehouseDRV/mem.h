#pragma once
#include <stdbool.h>
#include "definitions.h"

void getEPROCESS(PCHAR gameName);

bool writeMemory(void* address, void* buffer, size_t size);
bool writeToReadOnlyMemory(void* address, void* buffer, size_t size);

PVOID getSystemModuleBase(const char* moduleName);
PVOID getSystemModuleExport(const char* moduleName, LPCSTR routineName);