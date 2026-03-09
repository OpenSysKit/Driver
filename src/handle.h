#pragma once

#include "driver.h"

// 枚举指定进程（ProcessId=0 则枚举全系统）的句柄
NTSTATUS EnumHandles(ULONG ProcessId, PVOID OutputBuffer, ULONG OutputBufferSize, PULONG BytesWritten);

// 强制关闭指定进程中的句柄
NTSTATUS ForceCloseHandle(ULONG ProcessId, ULONG64 Handle);
