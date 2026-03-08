#pragma once

#include "driver.h"

// 将目标进程原地切换到指定 Token 级别，无需重启
// Level: ELEVATE_LEVEL_ADMIN / ELEVATE_LEVEL_SYSTEM /
//        ELEVATE_LEVEL_TRUSTED_INSTALLER / ELEVATE_LEVEL_STANDARD_USER
NTSTATUS ProcessElevate(ULONG ProcessId, ULONG Level);
