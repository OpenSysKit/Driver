#pragma once

#include <ntddk.h>

// 内核模式下未定义的进程访问权限常量
#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE           0x0001
#endif
#ifndef PROCESS_SUSPEND_RESUME
#define PROCESS_SUSPEND_RESUME      0x0800
#endif

// ========== 设备名 ==========

#define DEVICE_NAME    L"\\Device\\OpenSysKit"
#define SYMLINK_NAME   L"\\??\\OpenSysKit"

// ========== IOCTL 控制码 ==========
// 自定义设备类型，避免与系统冲突
#define DEVICE_TYPE_OPENSYSKIT  0x8000

#define IOCTL_ENUM_PROCESSES    CTL_CODE(DEVICE_TYPE_OPENSYSKIT, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KILL_PROCESS      CTL_CODE(DEVICE_TYPE_OPENSYSKIT, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FREEZE_PROCESS    CTL_CODE(DEVICE_TYPE_OPENSYSKIT, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UNFREEZE_PROCESS  CTL_CODE(DEVICE_TYPE_OPENSYSKIT, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PROTECT_PROCESS   CTL_CODE(DEVICE_TYPE_OPENSYSKIT, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UNPROTECT_PROCESS CTL_CODE(DEVICE_TYPE_OPENSYSKIT, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ========== 通信数据结构 ==========

// 请求：传入 PID
typedef struct _PROCESS_REQUEST {
    ULONG ProcessId;
} PROCESS_REQUEST, *PPROCESS_REQUEST;

// 响应：单个进程信息
typedef struct _PROCESS_INFO {
    ULONG  ProcessId;
    ULONG  ParentProcessId;
    ULONG  ThreadCount;
    SIZE_T WorkingSetSize;
    WCHAR  ImageName[260];
} PROCESS_INFO, *PPROCESS_INFO;

// 响应：进程列表头
typedef struct _PROCESS_LIST_HEADER {
    ULONG Count;
    ULONG TotalSize;
} PROCESS_LIST_HEADER, *PPROCESS_LIST_HEADER;

// ========== 进程保护 ==========

#define MAX_PROTECTED_PIDS 64

typedef struct _DRIVER_CONTEXT {
    PDEVICE_OBJECT DeviceObject;
    PVOID ObCallbackHandle;
    ULONG ProtectedPids[MAX_PROTECTED_PIDS];
    ULONG ProtectedPidCount;
    KSPIN_LOCK ProtectLock;
} DRIVER_CONTEXT, *PDRIVER_CONTEXT;

extern DRIVER_CONTEXT g_DriverContext;
