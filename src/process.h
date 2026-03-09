#pragma once

#include "driver.h"

// 在 DriverEntry 中调用一次，解析 PspTerminateThreadByPointer 地址
VOID ResolvePspTerminateThread();

// 进程枚举
NTSTATUS ProcessEnumerate(PVOID OutputBuffer, ULONG OutputBufferSize, PULONG BytesWritten);

// 内核级终止（优先 PspTerminateThreadByPointer，回退 ZwTerminateProcess）
NTSTATUS ProcessKill(ULONG ProcessId, PPROCESS_KILL_RESULT Result);

// 内核级删除文件（NT 路径，如 \??\C:\path\to\file.exe）
NTSTATUS FileDeleteKernel(PCWSTR Path);
