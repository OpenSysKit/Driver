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

// ========== PEPROCESS 直连终止路径解析 ==========

typedef NTSTATUS(NTAPI* PFN_PSP_TERMINATE_PROCESS)(PEPROCESS Process, NTSTATUS ExitStatus);

typedef enum _PROCESS_DIRECT_KILL_SOURCE {
    ProcessDirectKillSourceNone = 0,
    ProcessDirectKillSourcePsExport,
    ProcessDirectKillSourcePsResolvedTarget,
    ProcessDirectKillSourceZwResolvedTarget,
} PROCESS_DIRECT_KILL_SOURCE;

static PFN_PSP_TERMINATE_PROCESS g_PspTerminateProcess = nullptr;
static PROCESS_DIRECT_KILL_SOURCE g_ProcessDirectKillSource = ProcessDirectKillSourceNone;

static PCSTR ProcessDirectKillSourceName(_In_ PROCESS_DIRECT_KILL_SOURCE Source)
{
    switch (Source) {
    case ProcessDirectKillSourcePsExport:         return "PsTerminateProcess export";
    case ProcessDirectKillSourcePsResolvedTarget: return "PsTerminateProcess resolved target";
    case ProcessDirectKillSourceZwResolvedTarget: return "ZwTerminateProcess resolved target";
    default:                                      return "unresolved";
    }
}

// ---------- 工具函数 ----------

static BOOLEAN IsKernelAddress(PVOID addr)
{
    return (ULONG_PTR)addr > (ULONG_PTR)0xFFFF000000000000ULL;
}

static BOOLEAN ReadLongSafe(_In_ const VOID* Address, _Out_ PLONG Value)
{
    __try {
        *Value = *(const LONG*)Address;
        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

static BOOLEAN ReadPointerSafe(_In_ const VOID* Address, _Out_ PVOID* Value)
{
    __try {
        *Value = *(PVOID const*)Address;
        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        *Value = nullptr;
        return FALSE;
    }
}

static VOID LogStubBytes(_In_ PCSTR Tag, _In_opt_ PVOID Address, _In_ ULONG Count)
{
    UCHAR bytes[16] = {};
    ULONG copied = 0;

    if (!Address) {
        DbgPrint("[OpenSysKit] [%s] stub is null\n", Tag);
        return;
    }

    if (Count > RTL_NUMBER_OF(bytes)) Count = RTL_NUMBER_OF(bytes);

    __try {
        for (; copied < Count; ++copied)
            bytes[copied] = ((PUCHAR)Address)[copied];
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[OpenSysKit] [%s] failed to read stub bytes at %p\n", Tag, Address);
        return;
    }

    DbgPrint(
        "[OpenSysKit] [%s] head @%p: %02X %02X %02X %02X %02X %02X %02X %02X "
        "%02X %02X %02X %02X %02X %02X %02X %02X\n",
        Tag, Address,
        bytes[0],  bytes[1],  bytes[2],  bytes[3],
        bytes[4],  bytes[5],  bytes[6],  bytes[7],
        bytes[8],  bytes[9],  bytes[10], bytes[11],
        bytes[12], bytes[13], bytes[14], bytes[15]
    );
}

static VOID FillProcessKillResult(
    _Out_ PPROCESS_KILL_RESULT Result,
    _In_ ULONG Method,
    _In_ NTSTATUS OperationStatus)
{
    Result->Version         = PROCESS_KILL_RESULT_VERSION;
    Result->OperationStatus = (ULONG)OperationStatus;
    Result->Method          = Method;
    Result->Reserved        = 0;
}

//
// 验证一个函数指针是否指向合理的可执行内核代码。
// 检查：地址在内核空间 + 第一字节不是 int3/nop/零。
//
static BOOLEAN ValidateFunctionPointer(_In_ PVOID ptr)
{
    if (!ptr || !IsKernelAddress(ptr)) return FALSE;

    UCHAR firstByte = 0;
    __try {
        firstByte = *(PUCHAR)ptr;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }

    if (firstByte == 0xCC || firstByte == 0x90 || firstByte == 0x00) return FALSE;
    return TRUE;
}

//
// 从 stub 中找第一个控制转移指令，用于跟进 syscall stub -> 实现体。
//
static PVOID ScanStubTransfer(_In_ PVOID FuncBase, _In_ ULONG MaxScan, _In_opt_ PCSTR Tag)
{
    if (!FuncBase) return nullptr;
    PUCHAR p = (PUCHAR)FuncBase;

    for (ULONG i = 0; i < MaxScan; ++i) {
        UCHAR op = p[i];
        if (op == 0xC3 || op == 0xC2) break;

        if (op == 0xE8 || op == 0xE9) {
            if (i + 4 >= MaxScan) break;
            LONG rel = 0;
            if (!ReadLongSafe(p + i + 1, &rel)) continue;
            PVOID target = p + i + 5 + rel;
            if (IsKernelAddress(target)) {
                if (Tag) DbgPrint("[OpenSysKit] [%s] %s @+0x%02lX -> %p\n",
                    Tag, op == 0xE8 ? "rel32 call" : "rel32 jmp", i, target);
                return target;
            }
        }

        if (op == 0xEB) {
            if (i + 1 >= MaxScan) break;
            CHAR rel = (CHAR)p[i + 1];
            PVOID target = p + i + 2 + rel;
            if (IsKernelAddress(target)) {
                if (Tag) DbgPrint("[OpenSysKit] [%s] rel8 jmp @+0x%02lX -> %p\n", Tag, i, target);
                return target;
            }
        }

        if (op == 0xFF && i + 5 < MaxScan) {
            UCHAR modrm = p[i + 1];
            if (modrm == 0x15 || modrm == 0x25) {
                LONG disp = 0;
                if (!ReadLongSafe(p + i + 2, &disp)) continue;
                PVOID slot = p + i + 6 + disp;
                PVOID target = nullptr;
                if (ReadPointerSafe(slot, &target) && IsKernelAddress(target)) {
                    if (Tag) DbgPrint("[OpenSysKit] [%s] rip-indirect %s @+0x%02lX -> slot=%p target=%p\n",
                        Tag, modrm == 0x15 ? "call" : "jmp", i, slot, target);
                    return target;
                }
            }
        }
    }

    if (Tag) {
        DbgPrint("[OpenSysKit] [%s] no control-transfer within %lu bytes\n", Tag, MaxScan);
        LogStubBytes(Tag, FuncBase, 8);
    }
    return nullptr;
}

// ---------- 策略 1：PsTerminateProcess 导出 ----------

static PFN_PSP_TERMINATE_PROCESS ResolveViaPsTerminateProcess()
{
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"PsTerminateProcess");
    PVOID stub = MmGetSystemRoutineAddress(&name);
    if (!stub) {
        DbgPrint("[OpenSysKit] [Resolve#1] PsTerminateProcess export not found\n");
        return nullptr;
    }

    DbgPrint("[OpenSysKit] [Resolve#1] PsTerminateProcess export=%p\n", stub);
    LogStubBytes("Resolve#1", stub, 16);

    PVOID target = ScanStubTransfer(stub, 64, "Resolve#1");
    if (target && target != stub) {
        DbgPrint("[OpenSysKit] [Resolve#1] using resolved target: %p\n", target);
        g_ProcessDirectKillSource = ProcessDirectKillSourcePsResolvedTarget;
        return (PFN_PSP_TERMINATE_PROCESS)target;
    }

    DbgPrint("[OpenSysKit] [Resolve#1] using PsTerminateProcess export directly\n");
    g_ProcessDirectKillSource = ProcessDirectKillSourcePsExport;
    return (PFN_PSP_TERMINATE_PROCESS)stub;
}

// ---------- 策略 2：ZwTerminateProcess 调用链扫描 ----------
//
// NtTerminateProcess 结构大致如下：
//   [参数校验/权限检查，无 call]
//   ret                          <- 第一个 ret（快速失败路径）
//   ...
//   call PspTerminateProcess     <- 我们要找的目标
//   [线程终止循环：大量连续 call，目标地址等差递增]
//   ...
//
// 策略：
//   1. 跳过第一个 ret 之前（无 call）
//   2. 收集 ret 之后的 call，但跳过"等差 call 簇"
//      （连续多个 call 目标地址差值固定，判定为线程循环）
//   3. 取等差簇之前的最后一个孤立 call 作为 PspTerminateProcess
//
static PFN_PSP_TERMINATE_PROCESS ResolveViaZwTerminateProcess()
{
    const ULONG bodyScanLimit = 1024;
    // 连续几个 call 目标地址差值相同就认定为等差簇
    const ULONG clusterThreshold = 3;

    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"ZwTerminateProcess");
    PVOID zwStub = MmGetSystemRoutineAddress(&name);
    if (!zwStub) {
        DbgPrint("[OpenSysKit] [Resolve#2] ZwTerminateProcess export not found\n");
        return nullptr;
    }

    DbgPrint("[OpenSysKit] [Resolve#2] ZwTerminateProcess export=%p\n", zwStub);
    LogStubBytes("Resolve#2", zwStub, 16);

    // 跟进 syscall stub -> NtTerminateProcess 函数体
    PVOID body = ScanStubTransfer(zwStub, 64, "Resolve#2.stub");
    PUCHAR p = (PUCHAR)(body ? body : zwStub);

    if (body) {
        DbgPrint("[OpenSysKit] [Resolve#2] body candidate: %p\n", body);
        LogStubBytes("Resolve#2.body", body, 16);
    }

    // 第一阶段：收集所有 call 目标（带偏移），跳过第一个 ret 之前的部分
    const ULONG maxCalls = 128;
    ULONG_PTR callTargets[maxCalls] = {};
    ULONG callOffsets[maxCalls]     = {};
    ULONG callCount = 0;
    BOOLEAN passedFirstRet = FALSE;

    for (ULONG i = 0; i < bodyScanLimit && callCount < maxCalls; ++i) {
        UCHAR op = p[i];

        if (op == 0xC3 || op == 0xC2) {
            if (!passedFirstRet) {
                DbgPrint("[OpenSysKit] [Resolve#2.scan] first ret @+0x%03lX\n", i);
                passedFirstRet = TRUE;
            }
            continue;
        }

        // 只收集越过第一个 ret 之后的 call
        if (!passedFirstRet) continue;

        if (op == 0xE8) {
            if (i + 4 >= bodyScanLimit) break;
            LONG rel = 0;
            if (!ReadLongSafe(p + i + 1, &rel)) continue;
            PVOID target = p + i + 5 + rel;
            if (!IsKernelAddress(target)) continue;

            callTargets[callCount] = (ULONG_PTR)target;
            callOffsets[callCount] = i;
            DbgPrint("[OpenSysKit] [Resolve#2.scan] call[%lu] @+0x%03lX -> %p\n",
                callCount, i, target);
            callCount++;
        }
    }

    if (callCount == 0) {
        DbgPrint("[OpenSysKit] [Resolve#2] no calls found after first ret\n");
        return nullptr;
    }

    // 第二阶段：找等差簇起始位置，取簇之前最后一个孤立 call。
    //
    // 检测方法：从第二个 call 开始，计算相邻 call 目标地址差值，
    // 若连续 clusterThreshold 个差值相同则认定为等差簇。
    //
    ULONG clusterStart = callCount; // 默认没有簇

    if (callCount >= clusterThreshold + 1) {
        for (ULONG i = 1; i + clusterThreshold - 1 < callCount; ++i) {
            ULONG_PTR diff = callTargets[i] - callTargets[i - 1];
            if (diff == 0) continue; // 相同地址不算

            BOOLEAN isCluster = TRUE;
            for (ULONG j = i + 1; j <= i + clusterThreshold - 1; ++j) {
                if (callTargets[j] - callTargets[j - 1] != diff) {
                    isCluster = FALSE;
                    break;
                }
            }

            if (isCluster) {
                clusterStart = i - 1; // 簇从 i-1 开始（第一个参与等差的）
                DbgPrint("[OpenSysKit] [Resolve#2] cluster detected at call[%lu] "
                    "(diff=0x%llX), target before cluster: call[%lu] @+0x%03lX -> %p\n",
                    clusterStart, (ULONG64)diff,
                    clusterStart > 0 ? clusterStart - 1 : 0,
                    clusterStart > 0 ? callOffsets[clusterStart - 1] : 0,
                    clusterStart > 0 ? (PVOID)callTargets[clusterStart - 1] : nullptr);
                break;
            }
        }
    }

    // 取等差簇之前的最后一个 call
    ULONG targetIdx = (clusterStart > 0) ? clusterStart - 1 : callCount - 1;
    PVOID result = (PVOID)callTargets[targetIdx];

    DbgPrint("[OpenSysKit] [Resolve#2] selected call[%lu] @+0x%03lX -> %p as PspTerminateProcess candidate\n",
        targetIdx, callOffsets[targetIdx], result);

    g_ProcessDirectKillSource = ProcessDirectKillSourceZwResolvedTarget;
    return (PFN_PSP_TERMINATE_PROCESS)result;
}

// ---------- 主入口 ----------

VOID ResolvePspTerminateProcess()
{
    g_PspTerminateProcess     = nullptr;
    g_ProcessDirectKillSource = ProcessDirectKillSourceNone;

    g_PspTerminateProcess = ResolveViaPsTerminateProcess();
    if (g_PspTerminateProcess) {
        DbgPrint("[OpenSysKit] direct terminate path ready via %s: %p\n",
            ProcessDirectKillSourceName(g_ProcessDirectKillSource), g_PspTerminateProcess);
        return;
    }

    g_PspTerminateProcess = ResolveViaZwTerminateProcess();
    if (g_PspTerminateProcess) {
        DbgPrint("[OpenSysKit] direct terminate path ready via %s: %p\n",
            ProcessDirectKillSourceName(g_ProcessDirectKillSource), g_PspTerminateProcess);
        return;
    }

    DbgPrint("[OpenSysKit] direct terminate path unresolved, will fallback to ZwTerminateProcess handle path\n");
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

    // --- 路径 1：直连终止（PsTerminateProcess / PspTerminateProcess）---
    if (g_PspTerminateProcess && ValidateFunctionPointer((PVOID)g_PspTerminateProcess)) {
        PEPROCESS process = nullptr;
        NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
        if (NT_SUCCESS(status)) {
            // 检查 BreakOnTermination
            HANDLE hTmp = NULL;
            NTSTATUS qs = OpenProcessById(ProcessId, &hTmp, PROCESS_QUERY_LIMITED_INFORMATION);
            if (NT_SUCCESS(qs)) {
                ULONG breakOnTermination = 0;
                qs = ZwQueryInformationProcess(hTmp, ProcessBreakOnTermination,
                    &breakOnTermination, sizeof(breakOnTermination), NULL);
                ZwClose(hTmp);
                if (NT_SUCCESS(qs) && breakOnTermination != 0) {
                    ObDereferenceObject(process);
                    FillProcessKillResult(Result, PROCESS_KILL_METHOD_NONE, STATUS_ACCESS_DENIED);
                    return STATUS_SUCCESS;
                }
            }

            // SEH 保护：防止解析到错误地址时蓝屏
            NTSTATUS killStatus = STATUS_UNSUCCESSFUL;
            __try {
                killStatus = g_PspTerminateProcess(process, STATUS_SUCCESS);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                DbgPrint("[OpenSysKit] direct path exception 0x%08X, falling back to Zw\n",
                    GetExceptionCode());
                killStatus = STATUS_UNSUCCESSFUL;
            }

            ObDereferenceObject(process);

            if (NT_SUCCESS(killStatus)) {
                FillProcessKillResult(Result, PROCESS_KILL_METHOD_PSP, STATUS_SUCCESS);
                DbgPrint("[OpenSysKit] ProcessKill PID=%lu via %s OK\n",
                    ProcessId, ProcessDirectKillSourceName(g_ProcessDirectKillSource));
                return STATUS_SUCCESS;
            }
            DbgPrint("[OpenSysKit] direct path (%s) failed (0x%08X), falling back to Zw\n",
                ProcessDirectKillSourceName(g_ProcessDirectKillSource), killStatus);
        }
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