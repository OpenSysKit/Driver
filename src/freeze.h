#pragma once

#include "driver.h"

// 挂起进程所有线程（通过 PsSuspendThread）
NTSTATUS ProcessFreeze(ULONG ProcessId);

// 恢复进程所有线程（通过 PsResumeThread）
NTSTATUS ProcessUnfreeze(ULONG ProcessId);
