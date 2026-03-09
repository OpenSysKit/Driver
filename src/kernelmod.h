#pragma once

#include "driver.h"

// 枚举内核已加载模块（通过 PsLoadedModuleList）
NTSTATUS EnumKernelModules(PVOID OutputBuffer, ULONG OutputBufferSize, PULONG BytesWritten);
