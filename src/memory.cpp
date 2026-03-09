#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x0A000008
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include <ntifs.h>
#include "memory.h"

// ========== 进程内存读写 ==========
//
// MmCopyVirtualMemory 是未导出函数，通过 MmGetSystemRoutineAddress 无法获取，
// 改用 KeStackAttachProcess + 直接 ProbeAndRead/MoveMemory 的方案：
//   1. KeStackAttachProcess 附加到目标进程地址空间
//   2. ProbeForRead / ProbeForWrite 验证地址合法性
//   3. RtlCopyMemory 完成拷贝
//   4. KeUnstackDetachProcess 离开
//
// 全程在 __try/__except 保护内，避免页错误蓝屏。
//

NTSTATUS ProcessReadMemory(
    _In_  ULONG   ProcessId,
    _In_  ULONG64 Address,
    _Out_ PVOID   Buffer,
    _In_  ULONG   Size)
{
    if (!Buffer || Size == 0 || Size > PROCESS_MEMORY_MAX_SIZE)
        return STATUS_INVALID_PARAMETER;

    PEPROCESS process = nullptr;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status)) return status;

    KAPC_STATE apcState;
    KeStackAttachProcess(process, &apcState);

    __try {
        ProbeForRead((PVOID)Address, Size, 1);
        RtlCopyMemory(Buffer, (PVOID)Address, Size);
        status = STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        DbgPrint("[OpenSysKit] [Memory] ReadMemory PID=%lu addr=0x%llX exception: 0x%08X\n",
            ProcessId, Address, status);
    }

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(process);
    return status;
}

NTSTATUS ProcessWriteMemory(
    _In_ ULONG   ProcessId,
    _In_ ULONG64 Address,
    _In_ PVOID   Buffer,
    _In_ ULONG   Size)
{
    if (!Buffer || Size == 0 || Size > PROCESS_MEMORY_MAX_SIZE)
        return STATUS_INVALID_PARAMETER;

    PEPROCESS process = nullptr;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status)) return status;

    KAPC_STATE apcState;
    KeStackAttachProcess(process, &apcState);

    __try {
        ProbeForWrite((PVOID)Address, Size, 1);
        RtlCopyMemory((PVOID)Address, Buffer, Size);
        status = STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        DbgPrint("[OpenSysKit] [Memory] WriteMemory PID=%lu addr=0x%llX exception: 0x%08X\n",
            ProcessId, Address, status);
    }

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(process);
    return status;
}

// ========== 进程模块枚举 ==========
//
// 遍历目标进程的 PEB.Ldr（InLoadOrderModuleList）获取已加载模块列表。
// 在 KeStackAttachProcess 环境下读取用户态 PEB，全程异常保护。
//
// 注意：64 位驱动枚举 32 位进程时 PEB 地址通过 PsGetProcessWow64Process 获取，
//       此处仅处理 64 位进程（WOW64 留作扩展）。
//

// 用户态 LDR 数据结构（仅取需要的字段）
typedef struct _LDR_DATA_TABLE_ENTRY_PARTIAL {
    LIST_ENTRY  InLoadOrderLinks;
    LIST_ENTRY  InMemoryOrderLinks;
    LIST_ENTRY  InInitializationOrderLinks;
    PVOID       DllBase;
    PVOID       EntryPoint;
    ULONG       SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY_PARTIAL;

typedef struct _PEB_LDR_DATA_PARTIAL {
    ULONG       Length;
    BOOLEAN     Initialized;
    PVOID       SsHandle;
    LIST_ENTRY  InLoadOrderModuleList;
} PEB_LDR_DATA_PARTIAL;

// PEB 中 Ldr 字段偏移（x64 固定）
#define PEB_LDR_OFFSET  0x18

NTSTATUS ProcessEnumModules(
    _In_  ULONG  ProcessId,
    _Out_ PVOID  OutputBuffer,
    _In_  ULONG  OutputBufferSize,
    _Out_ PULONG BytesWritten)
{
    *BytesWritten = 0;

    if (OutputBufferSize < sizeof(MODULE_LIST_HEADER))
        return STATUS_BUFFER_TOO_SMALL;

    PEPROCESS process = nullptr;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status)) return status;

    PMODULE_LIST_HEADER header = (PMODULE_LIST_HEADER)OutputBuffer;
    PMODULE_INFO outEntry = (PMODULE_INFO)((PUCHAR)OutputBuffer + sizeof(MODULE_LIST_HEADER));
    ULONG maxEntries = (OutputBufferSize - sizeof(MODULE_LIST_HEADER)) / sizeof(MODULE_INFO);
    ULONG count = 0;

    KAPC_STATE apcState;
    KeStackAttachProcess(process, &apcState);

    __try {
        // 从 EPROCESS 取 PEB（PsGetProcessPeb 是未导出函数，用偏移读取）
        PVOID pPeb = PsGetProcessPeb(process);
        if (!pPeb) {
            status = STATUS_UNSUCCESSFUL;
            __leave;
        }

        ProbeForRead(pPeb, 0x20, 1);

        // PEB.Ldr
        PVOID pLdr = *(PVOID*)((PUCHAR)pPeb + PEB_LDR_OFFSET);
        if (!pLdr) {
            status = STATUS_UNSUCCESSFUL;
            __leave;
        }

        ProbeForRead(pLdr, sizeof(PEB_LDR_DATA_PARTIAL), 1);
        PEB_LDR_DATA_PARTIAL* ldr = (PEB_LDR_DATA_PARTIAL*)pLdr;

        PLIST_ENTRY head = &ldr->InLoadOrderModuleList;
        PLIST_ENTRY cur  = head->Flink;

        while (cur != head && count < maxEntries) {
            ProbeForRead(cur, sizeof(LDR_DATA_TABLE_ENTRY_PARTIAL), 1);
            LDR_DATA_TABLE_ENTRY_PARTIAL* entry =
                CONTAINING_RECORD(cur, LDR_DATA_TABLE_ENTRY_PARTIAL, InLoadOrderLinks);

            if (!entry->DllBase) {
                cur = cur->Flink;
                continue;
            }

            outEntry->BaseAddress  = (ULONG_PTR)entry->DllBase;
            outEntry->SizeOfImage  = entry->SizeOfImage;

            RtlZeroMemory(outEntry->FullPath,  sizeof(outEntry->FullPath));
            RtlZeroMemory(outEntry->BaseName,  sizeof(outEntry->BaseName));

            if (entry->FullDllName.Buffer && entry->FullDllName.Length > 0) {
                ProbeForRead(entry->FullDllName.Buffer, entry->FullDllName.Length, 1);
                USHORT copyLen = min(entry->FullDllName.Length,
                    (USHORT)(sizeof(outEntry->FullPath) - sizeof(WCHAR)));
                RtlCopyMemory(outEntry->FullPath, entry->FullDllName.Buffer, copyLen);
            }

            if (entry->BaseDllName.Buffer && entry->BaseDllName.Length > 0) {
                ProbeForRead(entry->BaseDllName.Buffer, entry->BaseDllName.Length, 1);
                USHORT copyLen = min(entry->BaseDllName.Length,
                    (USHORT)(sizeof(outEntry->BaseName) - sizeof(WCHAR)));
                RtlCopyMemory(outEntry->BaseName, entry->BaseDllName.Buffer, copyLen);
            }

            count++;
            outEntry++;
            cur = cur->Flink;
        }

        status = STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        DbgPrint("[OpenSysKit] [Memory] EnumModules PID=%lu exception: 0x%08X\n",
            ProcessId, status);
    }

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(process);

    if (NT_SUCCESS(status)) {
        header->Count     = count;
        header->TotalSize = sizeof(MODULE_LIST_HEADER) + count * sizeof(MODULE_INFO);
        *BytesWritten     = header->TotalSize;
    }

    return status;
}
