#pragma once
#include "driver.h"

// 从 EPROCESS 活动进程链表摘除（隐藏），最多同时隐藏 32 个进程
NTSTATUS HideProcess(ULONG ProcessId);

// 将已隐藏的进程重新插回链表（恢复可见性）
NTSTATUS UnhideProcess(ULONG ProcessId);
