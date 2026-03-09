#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x0A000008
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include <ntifs.h>
#include "process.h"

extern "C" NTSTATUS NTAPI ZwQuerySystemInformation(
    ULONG  SystemInformationClass,
    PVOID  SystemInformation,
    ULONG  SystemInformationLength,
    PULONG ReturnLength
);

extern "C" NTSTATUS NTAPI ZwQueryInformationProcess(
    HANDLE ProcessHandle,
    ULONG  ProcessInformationClass,
    PVOID  ProcessInformation,
    ULONG  ProcessInformationLength,
    PULONG ReturnLength
);

// 精准遍历指定进程的所有线程，返回线程持有引用，调用方须 ObDereferenceObject
extern "C" PETHREAD NTAPI PsGetNextProcessThread(
    _In_     PEPROCESS Process,
    _In_opt_ PETHREAD  Thread
);

#define SystemProcessInformation        5
#define ProcessBreakOnTermination       29

#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif

// ========== PspTerminateThreadByPointer 解析 ==========
//
// PsTerminateSystemThread 内部以 E9 rel32 跳转到 PspTerminateThreadByPointer，
// 扫描 0xFF 字节内定位目标地址。
//

typedef NTSTATUS(__fastcall* PFN_PSP_TERMINATE_THREAD)(
    PETHREAD pEThread,
    NTSTATUS ntExitCode,
    BOOLEAN  bDirectTerminate
);

static PFN_PSP_TERMINATE_THREAD g_PspTerminateThread = nullptr;

static PVOID SearchPattern(
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
        if (m >= patternSize) return (PVOID)(i + patternSize);
    }
    return nullptr;
}

VOID ResolvePspTerminateThread()
{
    g_PspTerminateThread = nullptr;

    UNICODE_STRING funcName;
    RtlInitUnicodeString(&funcName, L"PsTerminateSystemThread");
    PVOID pBase = MmGetSystemRoutineAddress(&funcName);
    if (!pBase) {
        DbgPrint("[OpenSysKit] [Resolve] PsTerminateSystemThread not found\n");
        return;
    }

    UCHAR pattern = 0xE9;
    PVOID pRelOffset = SearchPattern(
        pBase,
        (PVOID)((PUCHAR)pBase + 0xFF),
        &pattern, 1);

    DbgPrint("[OpenSysKit] [Resolve] PsTerminateSystemThread=%p\n", pPsTerminateSystemThread);

    PVOID pEnd = (PVOID)((PUCHAR)pPsTerminateSystemThread + 0xFF);

    // 先尝试 E9（jmp），再尝试 E8（call）
    UCHAR patternE9 = 0xE9;
    UCHAR patternE8 = 0xE8;

    PVOID pRelOffset = SearchMemory(pPsTerminateSystemThread, pEnd, &patternE9, 1);
    if (pRelOffset) {
        DbgPrint("[OpenSysKit] [Resolve] found E9\n");
    } else {
        pRelOffset = SearchMemory(pPsTerminateSystemThread, pEnd, &patternE8, 1);
        if (pRelOffset) {
            DbgPrint("[OpenSysKit] [Resolve] found E8\n");
        }
    }

    if (!pRelOffset) {
        DbgPrint("[OpenSysKit] [Resolve] neither E9 nor E8 found in PsTerminateSystemThread\n");
        return;
    }

    LONG  lOffset = *(PLONG)pRelOffset;
    PVOID pTarget = (PVOID)((PUCHAR)pRelOffset + sizeof(LONG) + lOffset);

    DbgPrint("[OpenSysKit] [Resolve] PspTerminateThreadByPointer=%p\n", pTarget);
    g_PspTerminateThread = (PFN_PSP_TERMINATE_THREAD)pTarget;
}

// ========== 系统进程信息结构 ==========

typedef struct _SYSTEM_PROCESS_INFORMATION_ENTRY {
    ULONG          NextEntryOffset;
    ULONG          NumberOfThreads;
    LARGE_INTEGER  Reserved[3];
    LARGE_INTEGER  CreateTime;
    LARGE_INTEGER  UserTime;
    LARGE_INTEGER  KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY      BasePriority;
    HANDLE         UniqueProcessId;
    HANDLE         InheritedFromUniqueProcessId;
    ULONG          HandleCount;
    ULONG          SessionId;
    ULONG_PTR      PageDirectoryBase;
    SIZE_T         PeakVirtualSize;
    SIZE_T         VirtualSize;
    ULONG          PageFaultCount;
    SIZE_T         PeakWorkingSetSize;
    SIZE_T         WorkingSetSize;
} SYSTEM_PROCESS_INFORMATION_ENTRY, *PSYSTEM_PROCESS_INFORMATION_ENTRY;

static VOID FillProcessKillResult(
    _Out_ PPROCESS_KILL_RESULT Result,
    _In_  ULONG    Method,
    _In_  NTSTATUS OperationStatus)
{
    Result->Version         = PROCESS_KILL_RESULT_VERSION;
    Result->OperationStatus = (ULONG)OperationStatus;
    Result->Method          = Method;
    Result->Reserved        = 0;
}

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

// ========== 辅助：打开进程句柄 ==========

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
//
// 路径 1：用 PsGetNextProcessThread 遍历目标进程所有线程，
//         逐一调用 PspTerminateThreadByPointer 终止。
//         PsGetNextProcessThread 对返回线程持有引用，处理完须 ObDereferenceObject。
//
// 路径 2：PspTerminateThreadByPointer 未解析或无线程可杀时，
//         回退到 ZwTerminateProcess。
//         终止前检查 ProcessBreakOnTermination，为关键进程时拒绝操作。
//

NTSTATUS ProcessKill(ULONG ProcessId, PPROCESS_KILL_RESULT Result)
{
    if (!Result) return STATUS_INVALID_PARAMETER;

    FillProcessKillResult(Result, PROCESS_KILL_METHOD_NONE, STATUS_UNSUCCESSFUL);

    if (ProcessId == 0 || ProcessId == 4) {
        FillProcessKillResult(Result, PROCESS_KILL_METHOD_NONE, STATUS_ACCESS_DENIED);
        return STATUS_ACCESS_DENIED;
    }

    // 路径 1：PspTerminateThreadByPointer
    if (g_PspTerminateThread) {
        PEPROCESS pTargetProcess = nullptr;
        NTSTATUS status = PsLookupProcessByProcessId(
            (HANDLE)(ULONG_PTR)ProcessId, &pTargetProcess);
        if (!NT_SUCCESS(status)) {
            FillProcessKillResult(Result, PROCESS_KILL_METHOD_PSP, status);
            return status;
        }

        ULONG killedThreads = 0;
        PETHREAD pThread = PsGetNextProcessThread(pTargetProcess, NULL);
        while (pThread != NULL) {
            __try {
                NTSTATUS killStatus = g_PspTerminateThread(pThread, 0, TRUE);
                if (NT_SUCCESS(killStatus)) killedThreads++;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                DbgPrint("[OpenSysKit] exception on thread %p: 0x%08X\n",
                    pThread, GetExceptionCode());
            }
            PETHREAD pNext = PsGetNextProcessThread(pTargetProcess, pThread);
            ObDereferenceObject(pThread);
            pThread = pNext;
        }

        ObDereferenceObject(pTargetProcess);

        DbgPrint("[OpenSysKit] ProcessKill PID=%lu via PspTerminateThread, killed=%lu\n",
            ProcessId, killedThreads);

        if (killedThreads > 0) {
            FillProcessKillResult(Result, PROCESS_KILL_METHOD_PSP, STATUS_SUCCESS);
            return STATUS_SUCCESS;
        }

        DbgPrint("[OpenSysKit] PID=%lu no threads killed, fallback to ZwTerminateProcess\n", ProcessId);
    }

    // 路径 2：ZwTerminateProcess
    HANDLE hProcess = NULL;
    NTSTATUS status = OpenProcessById(ProcessId, &hProcess,
        PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION);
    if (!NT_SUCCESS(status)) {
        FillProcessKillResult(Result, PROCESS_KILL_METHOD_ZW, status);
        return status;
    }

    ULONG breakOnTermination = 0;
    status = ZwQueryInformationProcess(hProcess, ProcessBreakOnTermination,
        &breakOnTermination, sizeof(breakOnTermination), NULL);
    if (!NT_SUCCESS(status)) {
        ZwClose(hProcess);
        FillProcessKillResult(Result, PROCESS_KILL_METHOD_ZW, status);
        return status;
    }
    if (breakOnTermination != 0) {
        ZwClose(hProcess);
        FillProcessKillResult(Result, PROCESS_KILL_METHOD_ZW, STATUS_ACCESS_DENIED);
        return STATUS_ACCESS_DENIED;
    }

    status = ZwTerminateProcess(hProcess, STATUS_SUCCESS);
    DbgPrint("[OpenSysKit] ProcessKill PID=%lu via ZwTerminateProcess: 0x%08X\n", ProcessId, status);
    ZwClose(hProcess);
    FillProcessKillResult(Result, PROCESS_KILL_METHOD_ZW, status);
    return status;
}

// ========== 文件删除 ==========
//
// 优先使用 FileDispositionInformationEx（Win10 1709+）：
//   POSIX_SEMANTICS            — 允许有其他 Handle 打开时仍能标记删除
//   IGNORE_READONLY_ATTRIBUTE  — 忽略只读属性限制
// 系统不支持时回退旧的 FileDispositionInformation。
//
// 入参须为 NT 绝对路径（\??\ 或 \Device\...），不接受 Win32 路径。
//

#define FileDispositionInformationEx            64
#define FILE_DISPOSITION_DELETE                 0x00000001
#define FILE_DISPOSITION_POSIX_SEMANTICS        0x00000002
#define FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE 0x00000010

typedef struct _FILE_DISPOSITION_INFORMATION_EX {
    ULONG Flags;
} FILE_DISPOSITION_INFORMATION_EX, *PFILE_DISPOSITION_INFORMATION_EX;

NTSTATUS FileDeleteKernel(PCWSTR Path)
{
    if (!Path || Path[0] == L'\0') return STATUS_INVALID_PARAMETER;
    if (Path[0] != L'\\')          return STATUS_INVALID_PARAMETER;

    SIZE_T pathLen = 0;
    while (Path[pathLen]) pathLen++;
    if (pathLen < 4) return STATUS_INVALID_PARAMETER;

    UNICODE_STRING ntPath;
    RtlInitUnicodeString(&ntPath, Path);

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &ntPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    IO_STATUS_BLOCK iosb = { 0 };
    HANDLE hFile = NULL;

    NTSTATUS status = ZwCreateFile(
        &hFile,
        DELETE | SYNCHRONIZE,
        &objAttr, &iosb, NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL, 0);
    if (!NT_SUCCESS(status)) return status;

    FILE_DISPOSITION_INFORMATION_EX dispEx = {
        FILE_DISPOSITION_DELETE |
        FILE_DISPOSITION_POSIX_SEMANTICS |
        FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE
    };
    status = ZwSetInformationFile(hFile, &iosb, &dispEx,
        sizeof(dispEx), (FILE_INFORMATION_CLASS)FileDispositionInformationEx);

    if (status == STATUS_INVALID_INFO_CLASS || status == STATUS_NOT_SUPPORTED) {
        FILE_DISPOSITION_INFORMATION disp = { TRUE };
        status = ZwSetInformationFile(hFile, &iosb, &disp,
            sizeof(disp), FileDispositionInformation);
    }

    ZwClose(hFile);
    return status;
}
