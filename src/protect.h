#pragma once

#include "driver.h"

// 在 DriverEntry 中调用一次，查找 EPROCESS.Protection 偏移
NTSTATUS InitProtect();

// 给指定 PID 设置 PPL-Antimalware 保护
NTSTATUS ProcessProtect(ULONG ProcessId);

// 取消保护，恢复原始 Protection 值
NTSTATUS ProcessUnprotect(ULONG ProcessId);

// 驱动卸载时调用，恢复所有被保护进程
VOID CleanupProtect();