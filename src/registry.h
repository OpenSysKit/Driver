#pragma once

#include "driver.h"

// 内核级删除注册表键（绕过 ACL，递归删除子键）
NTSTATUS RegDeleteKeyKernel(PCWSTR KeyPath);

// 内核级删除注册表值
NTSTATUS RegDeleteValueKernel(PCWSTR KeyPath, PCWSTR ValueName);
