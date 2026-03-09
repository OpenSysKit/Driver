#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x0A000008
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include <ntifs.h>
#include "registry.h"

// ========== 注册表操作 ==========
//
// 使用 ZwOpenKey / ZwDeleteKey / ZwDeleteValueKey 直接操作注册表。
// 路径须为 NT 格式：\Registry\Machine\... 或 \Registry\User\...
//
// RegDeleteKeyKernel 递归删除：先枚举并删除所有子键，再删除自身。
// 在内核模式下调用这些函数不经过用户态 ACL 检查，可删除受 ACL 保护的键。
//

extern "C" NTSTATUS NTAPI ZwQueryKey(
    HANDLE                KeyHandle,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID                 KeyInformation,
    ULONG                 Length,
    PULONG                ResultLength
);

extern "C" NTSTATUS NTAPI ZwEnumerateKey(
    HANDLE                KeyHandle,
    ULONG                 Index,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID                 KeyInformation,
    ULONG                 Length,
    PULONG                ResultLength
);

// 递归最大深度，防止畸形注册表死循环
#define REG_MAX_DEPTH 32

static NTSTATUS DeleteKeyRecursive(HANDLE hKey, ULONG depth)
{
    if (depth > REG_MAX_DEPTH) return STATUS_TOO_MANY_LEVELS;

    // 枚举子键，反复删除 index=0（删一个后列表前移，始终取第一个）
    while (TRUE) {
        ULONG infoSize = sizeof(KEY_BASIC_INFORMATION) + 512 * sizeof(WCHAR);
        PKEY_BASIC_INFORMATION info =
            (PKEY_BASIC_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, infoSize, 'regk');
        if (!info) return STATUS_INSUFFICIENT_RESOURCES;

        ULONG resultLen = 0;
        NTSTATUS status = ZwEnumerateKey(hKey, 0, KeyBasicInformation, info, infoSize, &resultLen);

        if (status == STATUS_NO_MORE_ENTRIES) {
            ExFreePoolWithTag(info, 'regk');
            break;
        }

        if (!NT_SUCCESS(status)) {
            ExFreePoolWithTag(info, 'regk');
            return status;
        }

        // 确保名称有 NUL 结尾
        ULONG nameLen = min(info->NameLength, (ULONG)(512 * sizeof(WCHAR) - sizeof(WCHAR)));
        info->Name[nameLen / sizeof(WCHAR)] = L'\0';

        UNICODE_STRING subName;
        RtlInitUnicodeString(&subName, info->Name);
        subName.Length = (USHORT)nameLen;

        OBJECT_ATTRIBUTES subAttr;
        InitializeObjectAttributes(&subAttr, &subName,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, hKey, NULL);

        HANDLE hSub = NULL;
        status = ZwOpenKey(&hSub, KEY_ALL_ACCESS, &subAttr);
        ExFreePoolWithTag(info, 'regk');

        if (!NT_SUCCESS(status)) return status;

        status = DeleteKeyRecursive(hSub, depth + 1);
        if (NT_SUCCESS(status))
            status = ZwDeleteKey(hSub);
        ZwClose(hSub);

        if (!NT_SUCCESS(status)) return status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS RegDeleteKeyKernel(PCWSTR KeyPath)
{
    if (!KeyPath || KeyPath[0] == L'\0') return STATUS_INVALID_PARAMETER;

    UNICODE_STRING keyName;
    RtlInitUnicodeString(&keyName, KeyPath);

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &keyName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE hKey = NULL;
    NTSTATUS status = ZwOpenKey(&hKey, KEY_ALL_ACCESS, &objAttr);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[OpenSysKit] [Reg] ZwOpenKey failed: 0x%08X (%ws)\n", status, KeyPath);
        return status;
    }

    status = DeleteKeyRecursive(hKey, 0);
    if (NT_SUCCESS(status))
        status = ZwDeleteKey(hKey);

    ZwClose(hKey);

    DbgPrint("[OpenSysKit] [Reg] DeleteKey %ws: 0x%08X\n", KeyPath, status);
    return status;
}

NTSTATUS RegDeleteValueKernel(PCWSTR KeyPath, PCWSTR ValueName)
{
    if (!KeyPath || !ValueName) return STATUS_INVALID_PARAMETER;

    UNICODE_STRING keyName;
    RtlInitUnicodeString(&keyName, KeyPath);

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &keyName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE hKey = NULL;
    NTSTATUS status = ZwOpenKey(&hKey, KEY_SET_VALUE, &objAttr);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[OpenSysKit] [Reg] ZwOpenKey for value failed: 0x%08X\n", status);
        return status;
    }

    UNICODE_STRING valueName;
    RtlInitUnicodeString(&valueName, ValueName);
    status = ZwDeleteValueKey(hKey, &valueName);

    ZwClose(hKey);

    DbgPrint("[OpenSysKit] [Reg] DeleteValue %ws / %ws: 0x%08X\n", KeyPath, ValueName, status);
    return status;
}
