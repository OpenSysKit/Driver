#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x0A000008
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include <ntifs.h>
#include "handle.h"

// ========== ZwQuerySystemInformation 句柄相关定义 ==========

extern "C" NTSTATUS NTAPI ZwQuerySystemInformation(
    ULONG  SystemInformationClass,
    PVOID  SystemInformation,
    ULONG  SystemInformationLength,
    PULONG ReturnLength
);

// SystemHandleInformation = 16
#define SystemHandleInformation 16

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR  ObjectTypeIndex;
    UCHAR  HandleAttributes;
    USHORT HandleValue;
    PVOID  Object;
    ULONG  GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

// ========== 对象名称查询 ==========
//
// ObQueryNameString 查询内核对象名称（如文件路径、注册表路径）。
// 对某些对象类型（如 Process）查询会触发额外引用，需限制查询范围。
//

static VOID QueryObjectName(
    _In_  PVOID  Object,
    _Out_ PWCHAR NameBuf,
    _In_  ULONG  NameBufChars)
{
    RtlZeroMemory(NameBuf, NameBufChars * sizeof(WCHAR));

    ULONG nameInfoSize = 512;
    POBJECT_NAME_INFORMATION nameInfo =
        (POBJECT_NAME_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, nameInfoSize, 'hndl');
    if (!nameInfo) return;

    ULONG returnLen = 0;
    NTSTATUS status = ObQueryNameString(Object, nameInfo, nameInfoSize, &returnLen);

    if (status == STATUS_INFO_LENGTH_MISMATCH && returnLen > 0 && returnLen <= 4096) {
        ExFreePoolWithTag(nameInfo, 'hndl');
        nameInfo = (POBJECT_NAME_INFORMATION)
            ExAllocatePool2(POOL_FLAG_NON_PAGED, returnLen, 'hndl');
        if (!nameInfo) return;
        status = ObQueryNameString(Object, nameInfo, returnLen, &returnLen);
    }

    if (NT_SUCCESS(status) && nameInfo->Name.Buffer && nameInfo->Name.Length > 0) {
        USHORT copyLen = min(nameInfo->Name.Length,
            (USHORT)((NameBufChars - 1) * sizeof(WCHAR)));
        RtlCopyMemory(NameBuf, nameInfo->Name.Buffer, copyLen);
    }

    ExFreePoolWithTag(nameInfo, 'hndl');
}

static VOID QueryObjectTypeName(
    _In_  PVOID  Object,
    _Out_ PWCHAR TypeBuf,
    _In_  ULONG  TypeBufChars)
{
    RtlZeroMemory(TypeBuf, TypeBufChars * sizeof(WCHAR));

    POBJECT_TYPE objType = ObGetObjectType(Object);
    if (!objType) return;

    // OBJECT_TYPE 内 Name 字段偏移在各版本一致（0x10）
    // 用公开的 ObGetObjectType 已经够了，类型名在对象类型结构里
    // 这里用一个简单可靠的方法：通过对象类型索引对应的已知名称
    // 直接查询 OBJECT_TYPE 内的 Name（UNICODE_STRING，偏移 0x10）
    UNICODE_STRING* typeName = (UNICODE_STRING*)((PUCHAR)objType + 0x10);

    __try {
        ProbeForRead(typeName, sizeof(UNICODE_STRING), 1);
        if (typeName->Buffer && typeName->Length > 0) {
            USHORT copyLen = min(typeName->Length,
                (USHORT)((TypeBufChars - 1) * sizeof(WCHAR)));
            ProbeForRead(typeName->Buffer, typeName->Length, 1);
            RtlCopyMemory(TypeBuf, typeName->Buffer, copyLen);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// ========== 公开接口 ==========

NTSTATUS EnumHandles(
    _In_  ULONG  ProcessId,
    _Out_ PVOID  OutputBuffer,
    _In_  ULONG  OutputBufferSize,
    _Out_ PULONG BytesWritten)
{
    *BytesWritten = 0;

    if (OutputBufferSize < sizeof(HANDLE_LIST_HEADER))
        return STATUS_BUFFER_TOO_SMALL;

    // 查询系统全局句柄表
    ULONG bufSize = 0;
    NTSTATUS status = ZwQuerySystemInformation(SystemHandleInformation, NULL, 0, &bufSize);
    if (status != STATUS_INFO_LENGTH_MISMATCH) return status;

    bufSize += 65536;
    PSYSTEM_HANDLE_INFORMATION sysHandles =
        (PSYSTEM_HANDLE_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, bufSize, 'hndl');
    if (!sysHandles) return STATUS_INSUFFICIENT_RESOURCES;

    status = ZwQuerySystemInformation(SystemHandleInformation, sysHandles, bufSize, &bufSize);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(sysHandles, 'hndl');
        return status;
    }

    PHANDLE_LIST_HEADER header = (PHANDLE_LIST_HEADER)OutputBuffer;
    PHANDLE_INFO outEntry = (PHANDLE_INFO)((PUCHAR)OutputBuffer + sizeof(HANDLE_LIST_HEADER));
    ULONG maxEntries = (OutputBufferSize - sizeof(HANDLE_LIST_HEADER)) / sizeof(HANDLE_INFO);
    ULONG count = 0;

    for (ULONG i = 0; i < sysHandles->NumberOfHandles && count < maxEntries; i++) {
        PSYSTEM_HANDLE_TABLE_ENTRY_INFO entry = &sysHandles->Handles[i];

        // 按 PID 过滤（ProcessId=0 返回全部）
        if (ProcessId != 0 && entry->UniqueProcessId != (USHORT)ProcessId)
            continue;

        outEntry->ProcessId       = entry->UniqueProcessId;
        outEntry->Handle          = entry->HandleValue;
        outEntry->ObjectTypeIndex = entry->ObjectTypeIndex;
        outEntry->GrantedAccess   = entry->GrantedAccess;
        outEntry->ObjectAddress   = (ULONG64)entry->Object;

        // 查询类型名和对象名（Object 是内核地址，直接使用）
        __try {
            QueryObjectTypeName(entry->Object, outEntry->TypeName,
                RTL_NUMBER_OF(outEntry->TypeName));
            QueryObjectName(entry->Object, outEntry->ObjectName,
                RTL_NUMBER_OF(outEntry->ObjectName));
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            // 查询失败留空，不影响其他字段
        }

        count++;
        outEntry++;
    }

    ExFreePoolWithTag(sysHandles, 'hndl');

    header->Count     = count;
    header->TotalSize = sizeof(HANDLE_LIST_HEADER) + count * sizeof(HANDLE_INFO);
    *BytesWritten     = header->TotalSize;

    DbgPrint("[OpenSysKit] [Handle] EnumHandles PID=%lu: %lu handles\n", ProcessId, count);
    return STATUS_SUCCESS;
}

//
// 强制关闭指定进程中的句柄：
//   附加到目标进程地址空间后调用 ZwClose，
//   此时 ZwClose 操作的是目标进程的句柄表。
//

NTSTATUS ForceCloseHandle(ULONG ProcessId, ULONG64 Handle)
{
    if (ProcessId == 0 || ProcessId == 4) return STATUS_ACCESS_DENIED;
    if (Handle == 0) return STATUS_INVALID_PARAMETER;

    PEPROCESS process = nullptr;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status)) return status;

    KAPC_STATE apcState;
    KeStackAttachProcess(process, &apcState);

    __try {
        status = ZwClose((HANDLE)Handle);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    KeUnstackDetachProcess(&apcState);
    ObDereferenceObject(process);

    DbgPrint("[OpenSysKit] [Handle] ForceCloseHandle PID=%lu handle=0x%llX: 0x%08X\n",
        ProcessId, Handle, status);
    return status;
}
