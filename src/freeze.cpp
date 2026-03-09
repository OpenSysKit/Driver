#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x0A000008
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include <ntifs.h>
#include "freeze.h"

// PsSuspendThread / PsResumeThread 未在公开头文件中导出
extern "C" NTSTATUS NTAPI PsSuspendThread(
    _In_  PETHREAD Thread,
    _Out_opt_ PULONG PreviousSuspendCount
);

extern "C" NTSTATUS NTAPI PsResumeThread(
    _In_  PETHREAD Thread,
    _Out_opt_ PULONG PreviousSuspendCount
);

extern "C" PETHREAD NTAPI PsGetNextProcessThread(
    _In_     PEPROCESS Process,
    _In_opt_ PETHREAD  Thread
);

// ========== 公开接口 ==========
//
// 遍历目标进程所有线程，逐一挂起或恢复。
// 对系统进程（PID 0/4）拒绝操作防止死锁。
//

static NTSTATUS FreezeUnfreezeProcess(ULONG ProcessId, BOOLEAN freeze)
{
    if (ProcessId == 0 || ProcessId == 4) return STATUS_ACCESS_DENIED;

    PEPROCESS process = nullptr;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status)) return status;

    ULONG count = 0;
    PETHREAD thread = PsGetNextProcessThread(process, NULL);
    while (thread != NULL) {
        __try {
            if (freeze)
                PsSuspendThread(thread, NULL);
            else
                PsResumeThread(thread, NULL);
            count++;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[OpenSysKit] [Freeze] exception on thread %p: 0x%08X\n",
                thread, GetExceptionCode());
        }

        PETHREAD next = PsGetNextProcessThread(process, thread);
        ObDereferenceObject(thread);
        thread = next;
    }

    ObDereferenceObject(process);

    DbgPrint("[OpenSysKit] [Freeze] PID=%lu %s, affected %lu threads\n",
        ProcessId, freeze ? "frozen" : "unfrozen", count);

    return (count > 0) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

NTSTATUS ProcessFreeze(ULONG ProcessId)
{
    return FreezeUnfreezeProcess(ProcessId, TRUE);
}

NTSTATUS ProcessUnfreeze(ULONG ProcessId)
{
    return FreezeUnfreezeProcess(ProcessId, FALSE);
}
