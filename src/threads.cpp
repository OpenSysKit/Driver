#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x0A000008
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include <ntifs.h>
#include "threads.h"

typedef PETHREAD (NTAPI* PFN_PS_GET_NEXT_PROCESS_THREAD)(
    _In_ PEPROCESS Process,
    _In_opt_ PETHREAD Thread
);

typedef PVOID (NTAPI* PFN_PS_GET_THREAD_WIN32_START_ADDRESS)(
    _In_ PETHREAD Thread
);

static PFN_PS_GET_THREAD_WIN32_START_ADDRESS ResolvePsGetThreadWin32StartAddress()
{
    static PFN_PS_GET_THREAD_WIN32_START_ADDRESS s_PsGetThreadWin32StartAddress = nullptr;
    static BOOLEAN s_Resolved = FALSE;

    if (!s_Resolved) {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"PsGetThreadWin32StartAddress");
        s_PsGetThreadWin32StartAddress =
            (PFN_PS_GET_THREAD_WIN32_START_ADDRESS)MmGetSystemRoutineAddress(&routineName);
        s_Resolved = TRUE;
    }

    return s_PsGetThreadWin32StartAddress;
}

static PFN_PS_GET_NEXT_PROCESS_THREAD ResolvePsGetNextProcessThread()
{
    static PFN_PS_GET_NEXT_PROCESS_THREAD s_PsGetNextProcessThread = nullptr;
    static BOOLEAN s_Resolved = FALSE;

    if (!s_Resolved) {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"PsGetNextProcessThread");
        s_PsGetNextProcessThread =
            (PFN_PS_GET_NEXT_PROCESS_THREAD)MmGetSystemRoutineAddress(&routineName);
        s_Resolved = TRUE;
    }

    return s_PsGetNextProcessThread;
}

// ========== 线程枚举 ==========
//
// 通过 PsGetNextProcessThread 遍历进程所有线程，
// 用公开导出函数取字段，不裸读 ETHREAD 偏移。
//   PsGetThreadId             → TID
//   KeQueryPriorityThread     → 当前优先级
//   PsGetThreadWin32StartAddress → 用户态起始地址
//   PsIsThreadTerminating     → 是否正在退出
//

NTSTATUS ProcessEnumThreads(
    _In_  ULONG  ProcessId,
    _Out_ PVOID  OutputBuffer,
    _In_  ULONG  OutputBufferSize,
    _Out_ PULONG BytesWritten)
{
    *BytesWritten = 0;
    PFN_PS_GET_THREAD_WIN32_START_ADDRESS getThreadWin32StartAddress =
        ResolvePsGetThreadWin32StartAddress();
    PFN_PS_GET_NEXT_PROCESS_THREAD getNextProcessThread = ResolvePsGetNextProcessThread();

    if (OutputBufferSize < sizeof(THREAD_LIST_HEADER))
        return STATUS_BUFFER_TOO_SMALL;

    if (!getNextProcessThread)
        return STATUS_PROCEDURE_NOT_FOUND;

    PEPROCESS process = nullptr;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status)) return status;

    PTHREAD_LIST_HEADER header   = (PTHREAD_LIST_HEADER)OutputBuffer;
    PTHREAD_INFO        outEntry = (PTHREAD_INFO)((PUCHAR)OutputBuffer + sizeof(THREAD_LIST_HEADER));
    ULONG maxEntries = (OutputBufferSize - sizeof(THREAD_LIST_HEADER)) / sizeof(THREAD_INFO);
    ULONG count = 0;

    PETHREAD thread = getNextProcessThread(process, NULL);
    while (thread != NULL && count < maxEntries) {
        outEntry->ThreadId      = (ULONG)(ULONG_PTR)PsGetThreadId(thread);
        outEntry->ProcessId     = ProcessId;
        outEntry->Priority      = (LONG)KeQueryPriorityThread(thread);
        outEntry->StartAddress  = getThreadWin32StartAddress
            ? (ULONG64)getThreadWin32StartAddress(thread)
            : 0;
        outEntry->IsTerminating = PsIsThreadTerminating(thread) ? TRUE : FALSE;

        count++;
        outEntry++;

        PETHREAD next = getNextProcessThread(process, thread);
        ObDereferenceObject(thread);
        thread = next;
    }

    // 释放剩余未处理的引用
    while (thread) {
        PETHREAD next = getNextProcessThread(process, thread);
        ObDereferenceObject(thread);
        thread = next;
    }

    ObDereferenceObject(process);

    header->Count     = count;
    header->TotalSize = sizeof(THREAD_LIST_HEADER) + count * sizeof(THREAD_INFO);
    *BytesWritten     = header->TotalSize;

    DbgPrint("[OpenSysKit] [Thread] PID=%lu: %lu threads\n", ProcessId, count);
    return STATUS_SUCCESS;
}
