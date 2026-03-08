#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x0A000008
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include <ntifs.h>
#include "process.h"

// ZwQuerySystemInformation 未在公开头文件中声明
extern "C" NTSTATUS NTAPI ZwQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

extern "C" NTSTATUS NTAPI ZwQueryInformationProcess(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

#define SystemProcessInformation 5
#define ProcessBreakOnTermination 29

#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif

// ========== PspTerminateThreadByPointer 解析 ==========
//
// Win10/11 x64 PsTerminateSystemThread 内部以 E9（rel32 jmp）跳转到
// PspTerminateThreadByPointer，扫描范围 0xFF 字节，非常稳定。
//
// 签名：NTSTATUS PspTerminateThreadByPointer(PETHREAD, NTSTATUS, BOOLEAN)
//
typedef NTSTATUS(__fastcall* PFN_PSP_TERMINATE_THREAD)(
    PETHREAD pEThread,
    NTSTATUS ntExitCode,
    BOOLEAN  bDirectTerminate
);

static PFN_PSP_TERMINATE_THREAD g_PspTerminateThread = nullptr;

//
// 在 [pStart, pEnd) 范围内搜索特征码，
// 返回特征码之后的地址（即 rel32 偏移所在位置）。
//
static PVOID SearchMemory(
    _In_ PVOID  pStart,
    _In_ PVOID  pEnd,
    _In_ PUCHAR pPattern,
    _In_ ULONG  patternSize)
{
    for (PUCHAR i = (PUCHAR)pStart; i < (PUCHAR)pEnd; i++) {
        ULONG m = 0;
        for (m = 0; m < patternSize; m++) {
            if (*(i + m) != pPattern[m]) break;
        }
        if (m >= patternSize) {
            return (PVOID)(i + patternSize);
        }
    }
    return nullptr;
}

VOID ResolvePspTerminateProcess()
{
    g_PspTerminateThread = nullptr;

    // Win10/11 x64 固定特征码 E9
    UCHAR pattern = 0xE9;

    UNICODE_STRING funcName;
    RtlInitUnicodeString(&funcName, L"PsTerminateSystemThread");
    PVOID pPsTerminateSystemThread = MmGetSystemRoutineAddress(&funcName);
    if (!pPsTerminateSystemThread) {
        DbgPrint("[OpenSysKit] [Resolve] PsTerminateSystemThread not found\n");
        return;
    }

    DbgPrint("[OpenSysKit] [Resolve] PsTerminateSystemThread=%p\n", pPsTerminateSystemThread);

    PVOID pRelOffset = SearchMemory(
        pPsTerminateSystemThread,
        (PVOID)((PUCHAR)pPsTerminateSystemThread + 0xFF),
        &pattern, 1
    );
    if (!pRelOffset) {
        DbgPrint("[OpenSysKit] [Resolve] E9 not found in PsTerminateSystemThread\n");
        return;
    }

    // 读取 rel32 偏移，计算目标地址
    LONG lOffset = *(PLONG)pRelOffset;
    PVOID pTarget = (PVOID)((PUCHAR)pRelOffset + sizeof(LONG) + lOffset);

    DbgPrint("[OpenSysKit] [Resolve] PspTerminateThreadByPointer=%p\n", pTarget);
    g_PspTerminateThread = (PFN_PSP_TERMINATE_THREAD)pTarget;
}

static VOID FillProcessKillResult(
    _Out_ PPROCESS_KILL_RESULT Result,
    _In_  ULONG   Method,
    _In_  NTSTATUS OperationStatus)
{
    Result->Version         = PROCESS_KILL_RESULT_VERSION;
    Result->OperationStatus = (ULONG)OperationStatus;
    Result->Method          = Method;
    Result->Reserved        = 0;
}

// ========== 系统进程信息结构 ==========

typedef struct _SYSTEM_PROCESS_INFORMATION_ENTRY {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER Reserved[3];
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR PageDirectoryBase;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
} SYSTEM_PROCESS_INFORMATION_ENTRY, *PSYSTEM_PROCESS_INFORMATION_ENTRY;

// ========== 进程枚举 ==========

NTSTATUS ProcessEnumerate(PVOID OutputBuffer, ULONG OutputBufferSize, PULONG BytesWritten)
{
    *BytesWritten = 0;

    ULONG bufferSize = 0;
    NTSTATUS status = ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &bufferSize);
    if (status != STATUS_INFO_LENGTH_MISMATCH) return status;

    bufferSize += 4096;
    PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, 'ksyS');
    if (!buffer) return STATUS_INSUFFICIENT_RESOURCES;

    status = ZwQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &bufferSize);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(buffer, 'ksyS');
        return status;
    }

    ULONG processCount = 0;
    PSYSTEM_PROCESS_INFORMATION_ENTRY entry = (PSYSTEM_PROCESS_INFORMATION_ENTRY)buffer;
    while (TRUE) {
        processCount++;
        if (entry->NextEntryOffset == 0) break;
        entry = (PSYSTEM_PROCESS_INFORMATION_ENTRY)((PUCHAR)entry + entry->NextEntryOffset);
    }

    if (OutputBufferSize < sizeof(PROCESS_LIST_HEADER)) {
        ExFreePoolWithTag(buffer, 'ksyS');
        return STATUS_BUFFER_TOO_SMALL;
    }

    PPROCESS_LIST_HEADER header = (PPROCESS_LIST_HEADER)OutputBuffer;
    header->TotalSize = sizeof(PROCESS_LIST_HEADER) + processCount * sizeof(PROCESS_INFO);

    ULONG maxEntries = (OutputBufferSize - sizeof(PROCESS_LIST_HEADER)) / sizeof(PROCESS_INFO);
    PPROCESS_INFO outEntry = (PPROCESS_INFO)((PUCHAR)OutputBuffer + sizeof(PROCESS_LIST_HEADER));

    entry = (PSYSTEM_PROCESS_INFORMATION_ENTRY)buffer;
    ULONG written = 0;
    while (TRUE) {
        if (written >= maxEntries) break;

        outEntry->ProcessId       = (ULONG)(ULONG_PTR)entry->UniqueProcessId;
        outEntry->ParentProcessId = (ULONG)(ULONG_PTR)entry->InheritedFromUniqueProcessId;
        outEntry->ThreadCount     = entry->NumberOfThreads;
        outEntry->WorkingSetSize  = entry->WorkingSetSize;

        RtlZeroMemory(outEntry->ImageName, sizeof(outEntry->ImageName));
        if (entry->ImageName.Buffer && entry->ImageName.Length > 0) {
            USHORT copyLen = min(entry->ImageName.Length,
                (USHORT)(sizeof(outEntry->ImageName) - sizeof(WCHAR)));
            RtlCopyMemory(outEntry->ImageName, entry->ImageName.Buffer, copyLen);
        }

        written++;
        outEntry++;

        if (entry->NextEntryOffset == 0) break;
        entry = (PSYSTEM_PROCESS_INFORMATION_ENTRY)((PUCHAR)entry + entry->NextEntryOffset);
    }

    header->Count = written;
    *BytesWritten = sizeof(PROCESS_LIST_HEADER) + written * sizeof(PROCESS_INFO);

    ExFreePoolWithTag(buffer, 'ksyS');
    return STATUS_SUCCESS;
}

// ========== 辅助：通过 PID 打开进程句柄 ==========

static NTSTATUS OpenProcessById(ULONG ProcessId, PHANDLE ProcessHandle, ACCESS_MASK Access)
{
    OBJECT_ATTRIBUTES objAttr;
    CLIENT_ID clientId;
    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)ProcessId;
    clientId.UniqueThread  = NULL;
    InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    return ZwOpenProcess(ProcessHandle, Access, &objAttr, &clientId);
}

// ========== 内核级终止 ==========

NTSTATUS ProcessKill(ULONG ProcessId, PPROCESS_KILL_RESULT Result)
{
    if (!Result) return STATUS_INVALID_PARAMETER;

    FillProcessKillResult(Result, PROCESS_KILL_METHOD_NONE, STATUS_UNSUCCESSFUL);

    if (ProcessId == 0 || ProcessId == 4) {
        FillProcessKillResult(Result, PROCESS_KILL_METHOD_NONE, STATUS_ACCESS_DENIED);
        return STATUS_SUCCESS;
    }

    // --- 路径 1：PspTerminateThreadByPointer 遍历线程终止 ---
    if (g_PspTerminateThread) {
        PEPROCESS pTargetProcess = nullptr;
        NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &pTargetProcess);
        if (!NT_SUCCESS(status)) {
            FillProcessKillResult(Result, PROCESS_KILL_METHOD_PSP, status);
            return STATUS_SUCCESS;
        }

        ULONG killedThreads = 0;

        for (ULONG tid = 4; tid < 0x80000; tid += 4) {
            PETHREAD pThread = nullptr;
            status = PsLookupThreadByThreadId((HANDLE)(ULONG_PTR)tid, &pThread);
            if (!NT_SUCCESS(status)) continue;

            PEPROCESS pThreadProcess = PsGetThreadProcess(pThread);
            if (pThreadProcess == pTargetProcess) {
                __try {
                    NTSTATUS killStatus = g_PspTerminateThread(pThread, 0, TRUE);
                    if (NT_SUCCESS(killStatus)) {
                        killedThreads++;
                        DbgPrint("[OpenSysKit] killed TID=%lu\n", tid);
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    DbgPrint("[OpenSysKit] exception on TID=%lu: 0x%08X\n",
                        tid, GetExceptionCode());
                }
            }

            // 每次 Lookup 必须 Dereference，否则可能蓝屏
            ObDereferenceObject(pThread);
        }

        ObDereferenceObject(pTargetProcess);

        DbgPrint("[OpenSysKit] ProcessKill PID=%lu via PspTerminateThreadByPointer, killed %lu threads\n",
            ProcessId, killedThreads);

        if (killedThreads > 0) {
            FillProcessKillResult(Result, PROCESS_KILL_METHOD_PSP, STATUS_SUCCESS);
            return STATUS_SUCCESS;
        }

        DbgPrint("[OpenSysKit] no threads found for PID=%lu, falling back to Zw\n", ProcessId);
    }

    // --- 路径 2：ZwTerminateProcess 回退 ---
    HANDLE hProcess = NULL;
    NTSTATUS status = OpenProcessById(ProcessId, &hProcess,
        PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION);
    if (!NT_SUCCESS(status)) {
        FillProcessKillResult(Result, PROCESS_KILL_METHOD_ZW, status);
        return STATUS_SUCCESS;
    }

    ULONG breakOnTermination = 0;
    status = ZwQueryInformationProcess(hProcess, ProcessBreakOnTermination,
        &breakOnTermination, sizeof(breakOnTermination), NULL);
    if (!NT_SUCCESS(status)) {
        ZwClose(hProcess);
        FillProcessKillResult(Result, PROCESS_KILL_METHOD_ZW, status);
        return STATUS_SUCCESS;
    }
    if (breakOnTermination != 0) {
        ZwClose(hProcess);
        FillProcessKillResult(Result, PROCESS_KILL_METHOD_ZW, STATUS_ACCESS_DENIED);
        return STATUS_SUCCESS;
    }

    status = ZwTerminateProcess(hProcess, STATUS_SUCCESS);
    DbgPrint("[OpenSysKit] ProcessKill PID=%lu via ZwTerminateProcess: 0x%08X\n", ProcessId, status);
    ZwClose(hProcess);
    FillProcessKillResult(Result, PROCESS_KILL_METHOD_ZW, status);
    return STATUS_SUCCESS;
}

// ========== 文件删除 ==========

NTSTATUS FileDeleteKernel(PCWSTR Path)
{
    if (!Path || Path[0] == L'\0') return STATUS_INVALID_PARAMETER;
    if (Path[0] != L'\\')         return STATUS_INVALID_PARAMETER;

    UNICODE_STRING ntPath;
    RtlInitUnicodeString(&ntPath, Path);

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &ntPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    IO_STATUS_BLOCK iosb = { 0 };
    HANDLE hFile = NULL;

    NTSTATUS status = ZwCreateFile(
        &hFile, DELETE | SYNCHRONIZE, &objAttr, &iosb, NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL, 0
    );
    if (!NT_SUCCESS(status)) return status;

    FILE_DISPOSITION_INFORMATION disposition = { 0 };
    disposition.DeleteFile = TRUE;

    status = ZwSetInformationFile(hFile, &iosb, &disposition,
        sizeof(disposition), FileDispositionInformation);

    ZwClose(hFile);
    return status;
}