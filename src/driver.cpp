#include "driver.h"
#include "signature.h"
#include "process.h"
#include "protect.h"
#include "token.h"
#include "freeze.h"
#include "memory.h"
#include "kernelmod.h"
#include "handle.h"
#include "registry.h"
#include "network.h"
#include "threads.h"
#include "inject.h"
#include "dkom.h"
#include "unload_driver.h"

DRIVER_CONTEXT g_DriverContext = { 0 };

static NTSTATUS DispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    SIGNATURE_STATUS sigStatus = VerifyCallerSignature();
    if (sigStatus != SignatureValid) {
        DbgPrint("[OpenSysKit] Caller signature verification failed: %d\n", sigStatus);
        Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_ACCESS_DENIED;
    }

    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG  ioctl  = irpSp->Parameters.DeviceIoControl.IoControlCode;
    PVOID  inBuf  = Irp->AssociatedIrp.SystemBuffer;
    PVOID  outBuf = Irp->AssociatedIrp.SystemBuffer;
    ULONG  inLen  = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG  outLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

    NTSTATUS status       = STATUS_SUCCESS;
    ULONG    bytesWritten = 0;

    ExAcquireFastMutex(&g_DriverContext.IoctlMutex);

    switch (ioctl) {

    // ===== 进程 =====

    case IOCTL_ENUM_PROCESSES:
        status = ProcessEnumerate(outBuf, outLen, &bytesWritten);
        break;

    case IOCTL_KILL_PROCESS:
        if (inLen < sizeof(PROCESS_REQUEST) || outLen < sizeof(PROCESS_KILL_RESULT)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        status = ProcessKill(((PPROCESS_REQUEST)inBuf)->ProcessId,
                             (PPROCESS_KILL_RESULT)outBuf);
        if (NT_SUCCESS(status))
            bytesWritten = sizeof(PROCESS_KILL_RESULT);
        break;

    case IOCTL_FREEZE_PROCESS:
        if (inLen < sizeof(PROCESS_REQUEST)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        status = ProcessFreeze(((PPROCESS_REQUEST)inBuf)->ProcessId);
        break;

    case IOCTL_UNFREEZE_PROCESS:
        if (inLen < sizeof(PROCESS_REQUEST)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        status = ProcessUnfreeze(((PPROCESS_REQUEST)inBuf)->ProcessId);
        break;

    case IOCTL_PROTECT_PROCESS:
        if (inLen < sizeof(PROCESS_REQUEST)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        status = ProcessProtect(((PPROCESS_REQUEST)inBuf)->ProcessId);
        break;

    case IOCTL_UNPROTECT_PROCESS:
        if (inLen < sizeof(PROCESS_REQUEST)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        status = ProcessUnprotect(((PPROCESS_REQUEST)inBuf)->ProcessId);
        break;

    case IOCTL_ELEVATE_PROCESS:
        if (inLen < sizeof(PROCESS_ELEVATE_REQUEST)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        {
            PPROCESS_ELEVATE_REQUEST req = (PPROCESS_ELEVATE_REQUEST)inBuf;
            status = ProcessElevate(req->ProcessId, req->Level);
        }
        break;

    case IOCTL_ENUM_MODULES:
        if (inLen < sizeof(PROCESS_REQUEST)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        status = ProcessEnumModules(((PPROCESS_REQUEST)inBuf)->ProcessId,
                                    outBuf, outLen, &bytesWritten);
        break;

    case IOCTL_ENUM_THREADS:
        if (inLen < sizeof(PROCESS_REQUEST)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        status = ProcessEnumThreads(((PPROCESS_REQUEST)inBuf)->ProcessId,
                                    outBuf, outLen, &bytesWritten);
        break;

    // 暂时禁用 - 能直接读写任意进程内存
    case IOCTL_READ_PROCESS_MEMORY:
    case IOCTL_WRITE_PROCESS_MEMORY:
        status = STATUS_NOT_SUPPORTED;
        break;

    // ===== 文件 =====

    case IOCTL_DELETE_FILE:
        if (inLen < sizeof(FILE_PATH_REQUEST)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        ((PFILE_PATH_REQUEST)inBuf)->Path[
            RTL_NUMBER_OF(((PFILE_PATH_REQUEST)inBuf)->Path) - 1] = L'\0';
        status = FileDeleteKernel(((PFILE_PATH_REQUEST)inBuf)->Path);
        break;

    // ===== 内核模块 =====

    case IOCTL_ENUM_KERNEL_MODULES:
        status = EnumKernelModules(outBuf, outLen, &bytesWritten);
        break;

    case IOCTL_UNLOAD_DRIVER:
        if (inLen < sizeof(DRIVER_SERVICE_REQUEST)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        {
            PDRIVER_SERVICE_REQUEST req = (PDRIVER_SERVICE_REQUEST)inBuf;
            req->ServiceName[RTL_NUMBER_OF(req->ServiceName) - 1] = L'\0';
            status = ForceUnloadDriver(req->ServiceName);
        }
        break;

    // ===== 句柄 =====

    case IOCTL_ENUM_HANDLES:
        if (inLen < sizeof(HANDLE_ENUM_REQUEST)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        status = EnumHandles(((PHANDLE_ENUM_REQUEST)inBuf)->ProcessId,
                             outBuf, outLen, &bytesWritten);
        break;

    case IOCTL_CLOSE_HANDLE:
        if (inLen < sizeof(CLOSE_HANDLE_REQUEST)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        {
            PCLOSE_HANDLE_REQUEST req = (PCLOSE_HANDLE_REQUEST)inBuf;
            status = ForceCloseHandle(req->ProcessId, req->Handle);
        }
        break;

    // 暂时禁用 - 可绕过 ACL 删除杀软注册表项
    case IOCTL_REG_DELETE_KEY:
    case IOCTL_REG_DELETE_VALUE:
        status = STATUS_NOT_SUPPORTED;
        break;

    // ===== 网络 =====

    case IOCTL_ENUM_CONNECTIONS:
        status = EnumConnections(outBuf, outLen, &bytesWritten);
        break;

    // ===== DLL 注入 =====
    // 暂时禁用 - 拿去干坏事怎么办
    case IOCTL_INJECT_DLL:
        status = STATUS_NOT_SUPPORTED;
        break;
        // if (inLen < sizeof(INJECT_DLL_REQUEST)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        // {
        //     PINJECT_DLL_REQUEST req = (PINJECT_DLL_REQUEST)inBuf;
        //     req->DllPath[RTL_NUMBER_OF(req->DllPath) - 1] = L'\0';
        //     status = InjectDll(req->ProcessId, req->DllPath);
        // }
        // break;

    // ===== DKOM 进程隐藏 =====

    case IOCTL_HIDE_PROCESS:
        if (inLen < sizeof(PROCESS_REQUEST)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        status = HideProcess(((PPROCESS_REQUEST)inBuf)->ProcessId);
        break;

    case IOCTL_UNHIDE_PROCESS:
        if (inLen < sizeof(PROCESS_REQUEST)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        status = UnhideProcess(((PPROCESS_REQUEST)inBuf)->ProcessId);
        break;

    // ===== 生命周期 =====

    case IOCTL_DETACH_SYMLINK:
    {
        UNICODE_STRING symLinkName;
        RtlInitUnicodeString(&symLinkName, SYMLINK_NAME);
        status = IoDeleteSymbolicLink(&symLinkName);
        DbgPrint("[OpenSysKit] IOCTL_DETACH_SYMLINK: 0x%X\n", status);
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    ExReleaseFastMutex(&g_DriverContext.IoctlMutex);

    Irp->IoStatus.Status      = status;
    Irp->IoStatus.Information = bytesWritten;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

static VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    DbgPrint("[OpenSysKit] >>> DRIVER UNLOADING <<<\n");

    // 保护在驱动卸载后继续有效，不在此恢复
    // CleanupProtect();

    CleanupSignatureVerification();

    UNICODE_STRING symLink;
    RtlInitUnicodeString(&symLink, SYMLINK_NAME);
    IoDeleteSymbolicLink(&symLink);

    if (g_DriverContext.DeviceObject) {
        IoDeleteDevice(g_DriverContext.DeviceObject);
        g_DriverContext.DeviceObject = NULL;
    }

    DbgPrint("[OpenSysKit] Driver unloaded\n");
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[OpenSysKit] ============================================\n");
    DbgPrint("[OpenSysKit] >>>    OPENSYSKIT DRIVER LOADING!       <<<\n");
    DbgPrint("[OpenSysKit] ============================================\n");

    if (!DriverObject) {
        DbgPrint("[OpenSysKit] ERROR: DriverObject is NULL!\n");
        return STATUS_INVALID_PARAMETER;
    }

    UNICODE_STRING deviceName, symLink;
    RtlInitUnicodeString(&deviceName, DEVICE_NAME);
    RtlInitUnicodeString(&symLink,    SYMLINK_NAME);

    IoDeleteSymbolicLink(&symLink);

    NTSTATUS status = IoCreateDevice(
        DriverObject, 0, &deviceName,
        FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN,
        FALSE, &g_DriverContext.DeviceObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[OpenSysKit] IoCreateDevice failed: 0x%X\n", status);
        return status;
    }

    status = IoCreateSymbolicLink(&symLink, &deviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[OpenSysKit] IoCreateSymbolicLink failed: 0x%X\n", status);
        IoDeleteDevice(g_DriverContext.DeviceObject);
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
    DriverObject->DriverUnload                          = DriverUnload;

    g_DriverContext.DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    ExInitializeFastMutex(&g_DriverContext.IoctlMutex);

    InitializeSignatureVerification();

    ResolvePspTerminateThread();

    status = InitProtect();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[OpenSysKit] InitProtect failed (0x%X); protection features disabled\n", status);
    }

    DbgPrint("[OpenSysKit] ============================================\n");
    DbgPrint("[OpenSysKit] >>>    DRIVER LOADED SUCCESSFULLY!      <<<\n");
    DbgPrint("[OpenSysKit] ============================================\n");
    return STATUS_SUCCESS;
}
