#pragma once
#include "driver.h"

// 通过内核 APC 向目标进程注入 DLL（Win32 路径）
NTSTATUS InjectDll(ULONG ProcessId, PCWSTR DllPath);
