#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x0A000008
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include <ntifs.h>
#include "freeze.h"

typedef NTSTATUS (NTAPI* PFN_PS_SUSPEND_THREAD)(
    _In_ PETHREAD Thread,
    _Out_opt_ PULONG PreviousSuspendCount
);

typedef NTSTATUS (NTAPI* PFN_PS_RESUME_THREAD)(
    _In_ PETHREAD Thread,
    _Out_opt_ PULONG PreviousSuspendCount
);

typedef PETHREAD (NTAPI* PFN_PS_GET_NEXT_PROCESS_THREAD)(
    _In_ PEPROCESS Process,
    _In_opt_ PETHREAD Thread
);

static PFN_PS_SUSPEND_THREAD ResolvePsSuspendThread()
{
    static PFN_PS_SUSPEND_THREAD s_PsSuspendThread = nullptr;
    static BOOLEAN s_Resolved = FALSE;

    if (!s_Resolved) {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"PsSuspendThread");
        s_PsSuspendThread = (PFN_PS_SUSPEND_THREAD)MmGetSystemRoutineAddress(&routineName);
        s_Resolved = TRUE;
    }

    return s_PsSuspendThread;
}

static PFN_PS_RESUME_THREAD ResolvePsResumeThread()
{
    static PFN_PS_RESUME_THREAD s_PsResumeThread = nullptr;
    static BOOLEAN s_Resolved = FALSE;

    if (!s_Resolved) {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"PsResumeThread");
        s_PsResumeThread = (PFN_PS_RESUME_THREAD)MmGetSystemRoutineAddress(&routineName);
        s_Resolved = TRUE;
    }

    return s_PsResumeThread;
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

// ========== 公开接口 ==========
//
// 遍历目标进程所有线程，逐一挂起或恢复。
// 对系统进程（PID 0/4）拒绝操作防止死锁。
//

static NTSTATUS FreezeUnfreezeProcess(ULONG ProcessId, BOOLEAN freeze)
{
    PFN_PS_GET_NEXT_PROCESS_THREAD getNextProcessThread = ResolvePsGetNextProcessThread();
    PFN_PS_SUSPEND_THREAD suspendThread = ResolvePsSuspendThread();
    PFN_PS_RESUME_THREAD resumeThread = ResolvePsResumeThread();

    if (!getNextProcessThread || (freeze && !suspendThread) || (!freeze && !resumeThread))
        return STATUS_PROCEDURE_NOT_FOUND;

    if (ProcessId == 0 || ProcessId == 4) return STATUS_ACCESS_DENIED;

    PEPROCESS process = nullptr;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status)) return status;

    ULONG count = 0;
    PETHREAD thread = getNextProcessThread(process, NULL);
    while (thread != NULL) {
        __try {
            if (freeze)
                suspendThread(thread, NULL);
            else
                resumeThread(thread, NULL);
            count++;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[OpenSysKit] [Freeze] exception on thread %p: 0x%08X\n",
                thread, GetExceptionCode());
        }

        PETHREAD next = getNextProcessThread(process, thread);
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
