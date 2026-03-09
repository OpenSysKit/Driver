#pragma once

#include "driver.h"

// 从目标进程读取内存，Size 最大 PROCESS_MEMORY_MAX_SIZE
NTSTATUS ProcessReadMemory(ULONG ProcessId, ULONG64 Address, PVOID Buffer, ULONG Size);

// 向目标进程写入内存
NTSTATUS ProcessWriteMemory(ULONG ProcessId, ULONG64 Address, PVOID Buffer, ULONG Size);

// 枚举目标进程已加载的模块（VAD 扫描 PE 头）
NTSTATUS ProcessEnumModules(ULONG ProcessId, PVOID OutputBuffer, ULONG OutputBufferSize, PULONG BytesWritten);
