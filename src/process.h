#pragma once

#include "driver.h"

// 在 DriverEntry 中调用一次，解析 PspTerminateProcess 地址
VOID ResolvePspTerminateProcess();

// 进程枚举
NTSTATUS ProcessEnumerate(PVOID OutputBuffer, ULONG OutputBufferSize, PULONG BytesWritten);

// 内核级终止（优先 PspTerminateProcess，回退 ZwTerminateProcess）
NTSTATUS ProcessKill(ULONG ProcessId);

// 内核级删除文件
NTSTATUS FileDeleteKernel(PCWSTR Path);