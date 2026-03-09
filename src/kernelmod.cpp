#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x0A000008
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include <ntifs.h>
#include "kernelmod.h"

// ========== 内核模块枚举 ==========
//
// 遍历 PsLoadedModuleList（LDR_DATA_TABLE_ENTRY 链表）。
// 持有 PsLoadedModuleResource 读锁保证遍历期间链表稳定，
// 遍历完成后立即释放。
//

extern "C" extern ERESOURCE PsLoadedModuleResource;

// LDR_DATA_TABLE_ENTRY 内核版（只取需要的字段）
typedef struct _KLDR_DATA_TABLE_ENTRY_PARTIAL {
    LIST_ENTRY     InLoadOrderLinks;
    PVOID          ExceptionTable;
    ULONG          ExceptionTableSize;
    PVOID          GpValue;
    PVOID          NonPagedDebugInfo;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} KLDR_DATA_TABLE_ENTRY_PARTIAL;

NTSTATUS EnumKernelModules(
    _Out_ PVOID  OutputBuffer,
    _In_  ULONG  OutputBufferSize,
    _Out_ PULONG BytesWritten)
{
    *BytesWritten = 0;

    if (OutputBufferSize < sizeof(KERNEL_MODULE_LIST_HEADER))
        return STATUS_BUFFER_TOO_SMALL;

    PKERNEL_MODULE_LIST_HEADER header = (PKERNEL_MODULE_LIST_HEADER)OutputBuffer;
    PKERNEL_MODULE_INFO outEntry =
        (PKERNEL_MODULE_INFO)((PUCHAR)OutputBuffer + sizeof(KERNEL_MODULE_LIST_HEADER));
    ULONG maxEntries =
        (OutputBufferSize - sizeof(KERNEL_MODULE_LIST_HEADER)) / sizeof(KERNEL_MODULE_INFO);

    // 读锁保护链表遍历
    ExAcquireResourceSharedLite(&PsLoadedModuleResource, TRUE);

    ULONG count = 0;
    PLIST_ENTRY head = PsLoadedModuleList;
    PLIST_ENTRY cur  = head->Flink;

    while (cur != head && count < maxEntries) {
        KLDR_DATA_TABLE_ENTRY_PARTIAL* entry =
            CONTAINING_RECORD(cur, KLDR_DATA_TABLE_ENTRY_PARTIAL, InLoadOrderLinks);

        outEntry->BaseAddress = (ULONG_PTR)entry->DllBase;
        outEntry->SizeOfImage = entry->SizeOfImage;

        RtlZeroMemory(outEntry->FullPath, sizeof(outEntry->FullPath));
        RtlZeroMemory(outEntry->BaseName, sizeof(outEntry->BaseName));

        if (entry->FullDllName.Buffer && entry->FullDllName.Length > 0) {
            USHORT copyLen = min(entry->FullDllName.Length,
                (USHORT)(sizeof(outEntry->FullPath) - sizeof(WCHAR)));
            RtlCopyMemory(outEntry->FullPath, entry->FullDllName.Buffer, copyLen);
        }

        if (entry->BaseDllName.Buffer && entry->BaseDllName.Length > 0) {
            USHORT copyLen = min(entry->BaseDllName.Length,
                (USHORT)(sizeof(outEntry->BaseName) - sizeof(WCHAR)));
            RtlCopyMemory(outEntry->BaseName, entry->BaseDllName.Buffer, copyLen);
        }

        count++;
        outEntry++;
        cur = cur->Flink;
    }

    ExReleaseResourceLite(&PsLoadedModuleResource);

    header->Count     = count;
    header->TotalSize = sizeof(KERNEL_MODULE_LIST_HEADER) + count * sizeof(KERNEL_MODULE_INFO);
    *BytesWritten     = header->TotalSize;

    DbgPrint("[OpenSysKit] [KernelMod] enumerated %lu kernel modules\n", count);
    return STATUS_SUCCESS;
}
