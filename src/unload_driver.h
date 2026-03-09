#pragma once
#include "driver.h"

// 强制卸载内核驱动（服务名，可含或不含 .sys）
NTSTATUS ForceUnloadDriver(PCWSTR ServiceName);
