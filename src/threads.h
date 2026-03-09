#pragma once
#include "driver.h"

NTSTATUS ProcessEnumThreads(ULONG ProcessId, PVOID OutputBuffer, ULONG OutputBufferSize, PULONG BytesWritten);
