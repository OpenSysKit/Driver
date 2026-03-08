#pragma once

#include "driver.h"

// 将目标进程原地提权到指定级别，无需重启
// Level: ELEVATE_LEVEL_ADMIN / ELEVATE_LEVEL_SYSTEM / ELEVATE_LEVEL_TRUSTED_INSTALLER
NTSTATUS ProcessElevate(ULONG ProcessId, ULONG Level);
