#pragma once

#include "driver.h"

// 枚举系统当前所有 TCP/UDP 连接及对应 PID
NTSTATUS EnumConnections(PVOID OutputBuffer, ULONG OutputBufferSize, PULONG BytesWritten);
