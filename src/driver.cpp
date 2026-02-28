#include "driver.h"
#include "process.h"

DRIVER_CONTEXT g_DriverContext = { 0 };

// callbacks.cpp
extern NTSTATUS RegisterProtectCallbacks();
extern void UnregisterProtectCallbacks();

static NTSTATUS DispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG ioctl = irpSp->Parameters.DeviceIoControl.IoControlCode;
    PVOID inBuf = Irp->AssociatedIrp.SystemBuffer;
    PVOID outBuf = Irp->AssociatedIrp.SystemBuffer;
    ULONG inLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytesWritten = 0;

    switch (ioctl) {
    case IOCTL_ENUM_PROCESSES:
        status = ProcessEnumerate(outBuf, outLen, &bytesWritten);
        break;

    case IOCTL_KILL_PROCESS:
        if (inLen < sizeof(PROCESS_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        status = ProcessKill(((PPROCESS_REQUEST)inBuf)->ProcessId);
        break;

    case IOCTL_FREEZE_PROCESS:
    case IOCTL_UNFREEZE_PROCESS:
        // 冻结/解冻由用户模式后端实现，驱动不处理
        status = STATUS_NOT_SUPPORTED;
        break;

    case IOCTL_PROTECT_PROCESS: {
        if (inLen < sizeof(PROCESS_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        ULONG pid = ((PPROCESS_REQUEST)inBuf)->ProcessId;
        KIRQL oldIrql;
        KeAcquireSpinLock(&g_DriverContext.ProtectLock, &oldIrql);
        if (g_DriverContext.ProtectedPidCount >= MAX_PROTECTED_PIDS) {
            status = STATUS_INSUFFICIENT_RESOURCES;
        } else {
            BOOLEAN found = FALSE;
            for (ULONG i = 0; i < g_DriverContext.ProtectedPidCount; i++) {
                if (g_DriverContext.ProtectedPids[i] == pid) {
                    found = TRUE;
                    break;
                }
            }
            if (!found) {
                g_DriverContext.ProtectedPids[g_DriverContext.ProtectedPidCount++] = pid;
            }
        }
        KeReleaseSpinLock(&g_DriverContext.ProtectLock, oldIrql);
        break;
    }

    case IOCTL_UNPROTECT_PROCESS: {
        if (inLen < sizeof(PROCESS_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        ULONG pid = ((PPROCESS_REQUEST)inBuf)->ProcessId;
        KIRQL oldIrql;
        KeAcquireSpinLock(&g_DriverContext.ProtectLock, &oldIrql);
        for (ULONG i = 0; i < g_DriverContext.ProtectedPidCount; i++) {
            if (g_DriverContext.ProtectedPids[i] == pid) {
                g_DriverContext.ProtectedPids[i] = g_DriverContext.ProtectedPids[g_DriverContext.ProtectedPidCount - 1];
                g_DriverContext.ProtectedPidCount--;
                break;
            }
        }
        KeReleaseSpinLock(&g_DriverContext.ProtectLock, oldIrql);
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesWritten;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

static void DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    UnregisterProtectCallbacks();

    // ObUnRegisterCallbacks 不保证其他 CPU 上正在执行的回调已完成，
    // 等待一段时间确保所有并发回调退出，防止映像内存释放后 use-after-free
    LARGE_INTEGER delay;
    delay.QuadPart = -10 * 1000 * 100; // 100ms (负值 = 相对时间, 单位 100ns)
    KeDelayExecutionThread(KernelMode, FALSE, &delay);

    UNICODE_STRING symLink = RTL_CONSTANT_STRING(SYMLINK_NAME);
    IoDeleteSymbolicLink(&symLink);

    if (g_DriverContext.DeviceObject) {
        IoDeleteDevice(g_DriverContext.DeviceObject);
        g_DriverContext.DeviceObject = NULL;
    }

    DbgPrint("[OpenSysKit] 驱动已卸载\n");
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[OpenSysKit] 驱动正在加载...\n");

    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(DEVICE_NAME);
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(SYMLINK_NAME);

    // 手动映射场景下，前一次卸载可能未完全清理符号链接，先尝试删除残留
    IoDeleteSymbolicLink(&symLink);

    NTSTATUS status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_DriverContext.DeviceObject
    );
    if (!NT_SUCCESS(status)) {
        DbgPrint("[OpenSysKit] 创建设备失败: 0x%X\n", status);
        return status;
    }

    status = IoCreateSymbolicLink(&symLink, &deviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[OpenSysKit] 创建符号链接失败: 0x%X\n", status);
        IoDeleteDevice(g_DriverContext.DeviceObject);
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
    DriverObject->DriverUnload = DriverUnload;

    // 手动映射场景下 I/O Manager 不会自动清除此标志，必须显式清除才能接受 CreateFile 请求
    g_DriverContext.DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    KeInitializeSpinLock(&g_DriverContext.ProtectLock);

    status = RegisterProtectCallbacks();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[OpenSysKit] 注册保护回调失败: 0x%X (保护功能不可用)\n", status);
        // 不阻止加载，保护功能降级
    }

    DbgPrint("[OpenSysKit] 驱动加载成功\n");
    return STATUS_SUCCESS;
}
