#pragma once

#include "driver.h"

// 进程枚举
NTSTATUS ProcessEnumerate(PVOID OutputBuffer, ULONG OutputBufferSize, PULONG BytesWritten);

// 内核级终止
NTSTATUS ProcessKill(ULONG ProcessId);
