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
// 通过 ZwQuerySystemInformation(SystemModuleInformation) 枚举内核模块，
// 避免直接依赖 PsLoadedModuleList / PsLoadedModuleResource 这类未文档化数据导出。
//

extern "C" NTSTATUS NTAPI ZwQuerySystemInformation(
    ULONG  SystemInformationClass,
    PVOID  SystemInformation,
    ULONG  SystemInformationLength,
    PULONG ReturnLength
);

#define SystemModuleInformation 11

typedef struct _SYSTEM_MODULE_ENTRY {
    HANDLE Section;
    PVOID  MappedBase;
    PVOID  ImageBase;
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
} SYSTEM_MODULE_ENTRY, *PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION_EX {
    ULONG NumberOfModules;
    SYSTEM_MODULE_ENTRY Modules[1];
} SYSTEM_MODULE_INFORMATION_EX, *PSYSTEM_MODULE_INFORMATION_EX;

static VOID CopyAnsiPathToWide(
    _Out_writes_(dstCount) PWCHAR dst,
    _In_ ULONG dstCount,
    _In_reads_(srcCount) const UCHAR* src,
    _In_ ULONG srcCount)
{
    ULONG limit = (dstCount > 0) ? dstCount - 1 : 0;
    ULONG i = 0;

    if (!dst || dstCount == 0)
        return;

    for (; i < srcCount && i < limit && src[i] != '\0'; ++i)
        dst[i] = (WCHAR)src[i];

    dst[i] = L'\0';
}

NTSTATUS EnumKernelModules(
    _Out_ PVOID  OutputBuffer,
    _In_  ULONG  OutputBufferSize,
    _Out_ PULONG BytesWritten)
{
    *BytesWritten = 0;

    if (OutputBufferSize < sizeof(KERNEL_MODULE_LIST_HEADER))
        return STATUS_BUFFER_TOO_SMALL;

    ULONG bufSize = 0;
    NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, nullptr, 0, &bufSize);
    if (status != STATUS_INFO_LENGTH_MISMATCH)
        return status;

    bufSize += 4096;
    PSYSTEM_MODULE_INFORMATION_EX modules = (PSYSTEM_MODULE_INFORMATION_EX)
        ExAllocatePool2(POOL_FLAG_NON_PAGED, bufSize, 'domK');
    if (!modules)
        return STATUS_INSUFFICIENT_RESOURCES;

    status = ZwQuerySystemInformation(SystemModuleInformation, modules, bufSize, &bufSize);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(modules, 'domK');
        return status;
    }

    PKERNEL_MODULE_LIST_HEADER header = (PKERNEL_MODULE_LIST_HEADER)OutputBuffer;
    PKERNEL_MODULE_INFO outEntry =
        (PKERNEL_MODULE_INFO)((PUCHAR)OutputBuffer + sizeof(KERNEL_MODULE_LIST_HEADER));
    ULONG maxEntries =
        (OutputBufferSize - sizeof(KERNEL_MODULE_LIST_HEADER)) / sizeof(KERNEL_MODULE_INFO);
    ULONG count = 0;

    for (ULONG i = 0; i < modules->NumberOfModules && count < maxEntries; ++i) {
        SYSTEM_MODULE_ENTRY* entry = &modules->Modules[i];
        ULONG fullPathLength = 0;
        ULONG baseOffset = entry->OffsetToFileName;

        while (fullPathLength < RTL_NUMBER_OF(entry->FullPathName) &&
               entry->FullPathName[fullPathLength] != '\0') {
            ++fullPathLength;
        }

        if (baseOffset > fullPathLength)
            baseOffset = fullPathLength;

        outEntry->BaseAddress = (ULONG_PTR)entry->ImageBase;
        outEntry->SizeOfImage = entry->ImageSize;
        RtlZeroMemory(outEntry->FullPath, sizeof(outEntry->FullPath));
        RtlZeroMemory(outEntry->BaseName, sizeof(outEntry->BaseName));

        CopyAnsiPathToWide(outEntry->FullPath, RTL_NUMBER_OF(outEntry->FullPath),
            entry->FullPathName, fullPathLength);
        CopyAnsiPathToWide(outEntry->BaseName, RTL_NUMBER_OF(outEntry->BaseName),
            entry->FullPathName + baseOffset, fullPathLength - baseOffset);

        ++count;
        ++outEntry;
    }

    ExFreePoolWithTag(modules, 'domK');

    header->Count     = count;
    header->TotalSize = sizeof(KERNEL_MODULE_LIST_HEADER) + count * sizeof(KERNEL_MODULE_INFO);
    *BytesWritten     = header->TotalSize;

    DbgPrint("[OpenSysKit] [KernelMod] enumerated %lu kernel modules\n", count);
    return STATUS_SUCCESS;
}
