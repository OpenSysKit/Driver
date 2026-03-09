#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x0A000008
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include <ntifs.h>
#include "unload_driver.h"

// ========== 强制卸载内核驱动 ==========
//
// 流程：
//   1. 通过 ObReferenceObjectByName("\Driver\<name>") 获取 DRIVER_OBJECT
//   2. 清零 DriverObject->DriverUnload，防止驱动在回调中返回失败拒绝卸载
//   3. 调用 ZwUnloadDriver 走系统卸载流程
//      路径格式：\Registry\Machine\SYSTEM\CurrentControlSet\Services\<name>
//
// ServiceName 可以带或不带 .sys 后缀，内部统一去掉。
// 仅适用于通过 SC/ZwLoadDriver 加载的驱动，内置驱动卸载会失败。
//

extern "C" extern POBJECT_TYPE* IoDriverObjectType;

static VOID StripSysSuffix(PCWSTR src, PWSTR dst, ULONG dstChars)
{
    SIZE_T len = 0;
    while (src[len]) len++;

    if (len > 4 && _wcsnicmp(src + len - 4, L".sys", 4) == 0)
        len -= 4;

    SIZE_T copy = len < dstChars - 1 ? len : dstChars - 1;
    RtlCopyMemory(dst, src, copy * sizeof(WCHAR));
    dst[copy] = L'\0';
}

NTSTATUS ForceUnloadDriver(PCWSTR ServiceName)
{
    if (!ServiceName || ServiceName[0] == L'\0') return STATUS_INVALID_PARAMETER;

    WCHAR cleanName[128] = {};
    StripSysSuffix(ServiceName, cleanName, RTL_NUMBER_OF(cleanName));
    if (cleanName[0] == L'\0') return STATUS_INVALID_PARAMETER;

    // 构造 \Driver\<name> 路径，尝试获取 DRIVER_OBJECT
    WCHAR drvPathBuf[160];
    UNICODE_STRING drvPath;
    drvPath.Buffer = drvPathBuf;
    drvPath.MaximumLength = sizeof(drvPathBuf);
    drvPath.Length = 0;
    RtlAppendUnicodeToString(&drvPath, L"\\Driver\\");
    RtlAppendUnicodeToString(&drvPath, cleanName);

    PDRIVER_OBJECT drvObj = nullptr;
    NTSTATUS status = ObReferenceObjectByName(
        &drvPath,
        OBJ_CASE_INSENSITIVE,
        NULL, 0,
        *IoDriverObjectType,
        KernelMode, NULL,
        (PVOID*)&drvObj);

    if (NT_SUCCESS(status) && drvObj) {
        // 清零 DriverUnload 防止驱动自行拒绝
        drvObj->DriverUnload = nullptr;
        ObDereferenceObject(drvObj);
        DbgPrint("[OpenSysKit] [Unload] cleared DriverUnload for \\Driver\\%ws\n", cleanName);
    } else {
        DbgPrint("[OpenSysKit] [Unload] ObReferenceObjectByName failed: 0x%08X (may be OK)\n",
            status);
    }

    // 构造服务注册表路径
    WCHAR regBuf[384];
    UNICODE_STRING regPath;
    regPath.Buffer = regBuf;
    regPath.MaximumLength = sizeof(regBuf);
    regPath.Length = 0;
    RtlAppendUnicodeToString(&regPath,
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\");
    RtlAppendUnicodeToString(&regPath, cleanName);

    status = ZwUnloadDriver(&regPath);
    DbgPrint("[OpenSysKit] [Unload] ZwUnloadDriver(%ws): 0x%08X\n", regBuf, status);
    return status;
}
