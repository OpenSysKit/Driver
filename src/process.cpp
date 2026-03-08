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
//
// 签名：NTSTATUS Ps/PspTerminateProcess(PEPROCESS Process, NTSTATUS ExitStatus)
//
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
    case ProcessDirectKillSourcePsExport:
        return "PsTerminateProcess export";
    case ProcessDirectKillSourcePsResolvedTarget:
        return "PsTerminateProcess resolved target";
    case ProcessDirectKillSourceZwResolvedTarget:
        return "ZwTerminateProcess resolved target";
    default:
        return "unresolved";
    }
}

// ---------- 工具：验证地址是否在内核空间 ----------

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
    UCHAR bytes[8] = {};
    ULONG copied = 0;

    if (!Address) {
        DbgPrint("[OpenSysKit] [%s] stub is null\n", Tag);
        return;
    }

    if (Count > RTL_NUMBER_OF(bytes)) {
        Count = RTL_NUMBER_OF(bytes);
    }

    __try {
        for (; copied < Count; ++copied) {
            bytes[copied] = ((PUCHAR)Address)[copied];
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[OpenSysKit] [%s] failed to read stub bytes at %p\n", Tag, Address);
        return;
    }

    DbgPrint(
        "[OpenSysKit] [%s] head @%p: %02X %02X %02X %02X %02X %02X %02X %02X\n",
        Tag,
        Address,
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5], bytes[6], bytes[7]
    );
}

static VOID FillProcessKillResult(
    _Out_ PPROCESS_KILL_RESULT Result,
    _In_ ULONG Method,
    _In_ NTSTATUS OperationStatus
)
{
    Result->Version = PROCESS_KILL_RESULT_VERSION;
    Result->OperationStatus = (ULONG)OperationStatus;
    Result->Method = Method;
    Result->Reserved = 0;
}

//
// 从函数 stub 中扫描常见的控制转移指令，提取目标地址。
// 这里仅做保守识别：rel32 call/jmp、rel8 jmp、RIP 相对的间接 call/jmp。
//
static PVOID ScanStubTransfer(_In_ PVOID FuncBase, _In_ ULONG MaxScan, _In_opt_ PCSTR Tag)
{
    PUCHAR p = (PUCHAR)FuncBase;

    if (!FuncBase) {
        return nullptr;
    }

    for (ULONG i = 0; i < MaxScan; ++i) {
        UCHAR opcode = p[i];
        if (opcode == 0xC3 || opcode == 0xC2) {
            break;
        }

        if (opcode == 0xE8 || opcode == 0xE9) {
            if (i + 4 >= MaxScan) {
                break;
            }

            LONG rel = 0;
            if (!ReadLongSafe(p + i + 1, &rel)) {
                continue;
            }

            PVOID target = p + i + 5 + rel;
            if (IsKernelAddress(target)) {
                if (Tag) {
                    DbgPrint(
                        "[OpenSysKit] [%s] %s @+0x%02lX -> %p\n",
                        Tag,
                        (opcode == 0xE8) ? "rel32 call" : "rel32 jmp",
                        i,
                        target
                    );
                }
                return target;
            }
            continue;
        }

        if (opcode == 0xEB) {
            if (i + 1 >= MaxScan) {
                break;
            }

            CHAR rel = (CHAR)p[i + 1];
            PVOID target = p + i + 2 + rel;
            if (IsKernelAddress(target)) {
                if (Tag) {
                    DbgPrint("[OpenSysKit] [%s] rel8 jmp @+0x%02lX -> %p\n", Tag, i, target);
                }
                return target;
            }
            continue;
        }

        if (opcode == 0xFF) {
            if (i + 5 >= MaxScan) {
                break;
            }

            UCHAR modrm = p[i + 1];
            if (modrm == 0x15 || modrm == 0x25) {
                LONG disp = 0;
                if (!ReadLongSafe(p + i + 2, &disp)) {
                    continue;
                }

                PVOID slot = p + i + 6 + disp;
                PVOID target = nullptr;
                if (ReadPointerSafe(slot, &target) && IsKernelAddress(target)) {
                    if (Tag) {
                        DbgPrint(
                            "[OpenSysKit] [%s] rip-indirect %s @+0x%02lX -> slot=%p target=%p\n",
                            Tag,
                            (modrm == 0x15) ? "call" : "jmp",
                            i,
                            slot,
                            target
                        );
                    }
                    return target;
                }
            }
        }
    }

    if (Tag) {
        DbgPrint("[OpenSysKit] [%s] no recognized control-transfer pattern within %lu bytes\n", Tag, MaxScan);
        LogStubBytes(Tag, FuncBase, 8);
    }
    return nullptr;
}

static PFN_PSP_TERMINATE_PROCESS ResolvePsTerminateProcessExport()
{
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"PsTerminateProcess");

    PVOID stub = MmGetSystemRoutineAddress(&name);
    if (!stub) {
        DbgPrint("[OpenSysKit] [Resolve#1] PsTerminateProcess export not found\n");
        return nullptr;
    }

    DbgPrint("[OpenSysKit] [Resolve#1] PsTerminateProcess export=%p\n", stub);
    LogStubBytes("Resolve#1", stub, 8);
    return (PFN_PSP_TERMINATE_PROCESS)stub;
}

// ---------- 策略 1：优先直接使用 PsTerminateProcess 导出 ----------
//
// 对当前系统来说，这条路径比扫描内部 Psp 更稳；若 stub 能进一步解析到内部目标，
// 则优先使用解析结果，否则直接使用导出入口本身。
//
static PFN_PSP_TERMINATE_PROCESS ResolveViaPsTerminateProcess()
{
    PFN_PSP_TERMINATE_PROCESS exportEntry = ResolvePsTerminateProcessExport();
    if (!exportEntry) {
        return nullptr;
    }

    PVOID target = ScanStubTransfer((PVOID)exportEntry, 64, "Resolve#1");
    if (target && target != (PVOID)exportEntry) {
        DbgPrint("[OpenSysKit] [Resolve#1] using resolved target behind PsTerminateProcess: %p\n", target);
        g_ProcessDirectKillSource = ProcessDirectKillSourcePsResolvedTarget;
        return (PFN_PSP_TERMINATE_PROCESS)target;
    }

    DbgPrint("[OpenSysKit] [Resolve#1] using PsTerminateProcess export directly\n");
    g_ProcessDirectKillSource = ProcessDirectKillSourcePsExport;
    return exportEntry;
}

// ---------- 策略 2：ZwTerminateProcess 调用链扫描（备用）----------
//
// 若 PsTerminateProcess 导出不可用，则尝试沿 ZwTerminateProcess 的导出 stub 找到
// 内部实现，再从其函数体中提取最后一个合理的 call 目标作为候选。
//
static PFN_PSP_TERMINATE_PROCESS ResolveViaZwTerminateProcess()
{
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"ZwTerminateProcess");

    PVOID zwStub = MmGetSystemRoutineAddress(&name);
    if (!zwStub) {
        DbgPrint("[OpenSysKit] [Resolve#2] ZwTerminateProcess export not found\n");
        return nullptr;
    }

    DbgPrint("[OpenSysKit] [Resolve#2] ZwTerminateProcess export=%p\n", zwStub);
    LogStubBytes("Resolve#2", zwStub, 8);

    PVOID body = ScanStubTransfer(zwStub, 64, "Resolve#2.stub");
    PUCHAR p = (PUCHAR)(body ? body : zwStub);
    PVOID lastCandidate = nullptr;

    if (body) {
        DbgPrint("[OpenSysKit] [Resolve#2] using ZwTerminateProcess body candidate: %p\n", body);
    }

    for (ULONG i = 0; i < 256; i++) {
        if (p[i] == 0xC3 || p[i] == 0xC2) {
            break;
        }

        if (p[i] == 0xE8) {
            if (i + 4 >= 256) {
                break;
            }

            LONG rel = 0;
            if (!ReadLongSafe(p + i + 1, &rel)) {
                continue;
            }

            PVOID target = p + i + 5 + rel;
            if (IsKernelAddress(target)) {
                lastCandidate = target;
            }
            continue;
        }

        if (i + 5 < 256 && p[i] == 0xFF && p[i + 1] == 0x15) {
            LONG disp = 0;
            if (!ReadLongSafe(p + i + 2, &disp)) {
                continue;
            }

            PVOID slot = p + i + 6 + disp;
            PVOID target = nullptr;
            if (ReadPointerSafe(slot, &target) && IsKernelAddress(target)) {
                lastCandidate = target;
            }
        }
    }

    if (lastCandidate) {
        DbgPrint("[OpenSysKit] [Resolve#2] ZwTerminateProcess scan -> %p\n", lastCandidate);
        g_ProcessDirectKillSource = ProcessDirectKillSourceZwResolvedTarget;
        return (PFN_PSP_TERMINATE_PROCESS)lastCandidate;
    }

    DbgPrint("[OpenSysKit] [Resolve#2] no call candidate found in ZwTerminateProcess body\n");
    return nullptr;
}

// ---------- 主入口 ----------

VOID ResolvePspTerminateProcess()
{
    g_PspTerminateProcess = nullptr;
    g_ProcessDirectKillSource = ProcessDirectKillSourceNone;

    g_PspTerminateProcess = ResolveViaPsTerminateProcess();
    if (g_PspTerminateProcess) {
        DbgPrint(
            "[OpenSysKit] direct terminate path ready via %s: %p\n",
            ProcessDirectKillSourceName(g_ProcessDirectKillSource),
            g_PspTerminateProcess
        );
        return;
    }

    g_PspTerminateProcess = ResolveViaZwTerminateProcess();
    if (g_PspTerminateProcess) {
        DbgPrint(
            "[OpenSysKit] direct terminate path ready via %s: %p\n",
            ProcessDirectKillSourceName(g_ProcessDirectKillSource),
            g_PspTerminateProcess
        );
        return;
    }

    DbgPrint("[OpenSysKit] direct terminate path unresolved, will fallback to ZwTerminateProcess handle path\n");
}

// ========== 系统进程信息结构（部分字段）==========

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
    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        return status;
    }

    bufferSize += 4096;
    PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, 'ksyS');
    if (!buffer) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

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

    ULONG requiredSize = sizeof(PROCESS_LIST_HEADER) + processCount * sizeof(PROCESS_INFO);
    if (OutputBufferSize < sizeof(PROCESS_LIST_HEADER)) {
        ExFreePoolWithTag(buffer, 'ksyS');
        return STATUS_BUFFER_TOO_SMALL;
    }

    PPROCESS_LIST_HEADER header = (PPROCESS_LIST_HEADER)OutputBuffer;
    header->TotalSize = requiredSize;

    ULONG maxEntries = (OutputBufferSize - sizeof(PROCESS_LIST_HEADER)) / sizeof(PROCESS_INFO);
    PPROCESS_INFO outEntry = (PPROCESS_INFO)((PUCHAR)OutputBuffer + sizeof(PROCESS_LIST_HEADER));

    entry = (PSYSTEM_PROCESS_INFORMATION_ENTRY)buffer;
    ULONG written = 0;
    while (TRUE) {
        if (written >= maxEntries) break;

        outEntry->ProcessId = (ULONG)(ULONG_PTR)entry->UniqueProcessId;
        outEntry->ParentProcessId = (ULONG)(ULONG_PTR)entry->InheritedFromUniqueProcessId;
        outEntry->ThreadCount = entry->NumberOfThreads;
        outEntry->WorkingSetSize = entry->WorkingSetSize;

        RtlZeroMemory(outEntry->ImageName, sizeof(outEntry->ImageName));
        if (entry->ImageName.Buffer && entry->ImageName.Length > 0) {
            USHORT copyLen = min(entry->ImageName.Length, (USHORT)(sizeof(outEntry->ImageName) - sizeof(WCHAR)));
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
    clientId.UniqueThread = NULL;
    InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    return ZwOpenProcess(ProcessHandle, Access, &objAttr, &clientId);
}

// ========== 内核级终止 ==========

NTSTATUS ProcessKill(ULONG ProcessId, PPROCESS_KILL_RESULT Result)
{
    if (!Result) {
        return STATUS_INVALID_PARAMETER;
    }

    FillProcessKillResult(Result, PROCESS_KILL_METHOD_NONE, STATUS_UNSUCCESSFUL);

    if (ProcessId == 0 || ProcessId == 4) {
        FillProcessKillResult(Result, PROCESS_KILL_METHOD_NONE, STATUS_ACCESS_DENIED);
        return STATUS_SUCCESS;
    }

    // --- 路径 1：直连终止路径（优先 PsTerminateProcess 导出/解析目标）---
    if (g_PspTerminateProcess) {
        PEPROCESS process = nullptr;
        NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
        if (NT_SUCCESS(status)) {
            HANDLE hTmp = NULL;
            NTSTATUS queryStatus = OpenProcessById(ProcessId, &hTmp, PROCESS_QUERY_LIMITED_INFORMATION);
            if (NT_SUCCESS(queryStatus)) {
                ULONG breakOnTermination = 0;
                queryStatus = ZwQueryInformationProcess(
                    hTmp, ProcessBreakOnTermination,
                    &breakOnTermination, sizeof(breakOnTermination), NULL
                );
                ZwClose(hTmp);

                if (NT_SUCCESS(queryStatus) && breakOnTermination != 0) {
                    ObDereferenceObject(process);
                    FillProcessKillResult(Result, PROCESS_KILL_METHOD_NONE, STATUS_ACCESS_DENIED);
                    return STATUS_SUCCESS;
                }
            }

            status = g_PspTerminateProcess(process, STATUS_SUCCESS);
            ObDereferenceObject(process);

            if (NT_SUCCESS(status)) {
                FillProcessKillResult(Result, PROCESS_KILL_METHOD_PSP, STATUS_SUCCESS);
                DbgPrint(
                    "[OpenSysKit] ProcessKill PID=%lu via direct path (%s) OK\n",
                    ProcessId,
                    ProcessDirectKillSourceName(g_ProcessDirectKillSource)
                );
                return STATUS_SUCCESS;
            }
            DbgPrint(
                "[OpenSysKit] direct path (%s) failed (0x%08X), falling back to Zw\n",
                ProcessDirectKillSourceName(g_ProcessDirectKillSource),
                status
            );
        }
    }

    // --- 路径 2：ZwTerminateProcess 回退 ---
    HANDLE hProcess = NULL;
    NTSTATUS status = OpenProcessById(
        ProcessId, &hProcess,
        PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION
    );
    if (!NT_SUCCESS(status)) {
        FillProcessKillResult(Result, PROCESS_KILL_METHOD_ZW, status);
        return STATUS_SUCCESS;
    }

    ULONG breakOnTermination = 0;
    status = ZwQueryInformationProcess(
        hProcess, ProcessBreakOnTermination,
        &breakOnTermination, sizeof(breakOnTermination), NULL
    );
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
    if (!Path || Path[0] == L'\0') {
        return STATUS_INVALID_PARAMETER;
    }

    if (Path[0] != L'\\') {
        return STATUS_INVALID_PARAMETER;
    }

    UNICODE_STRING ntPath;
    RtlInitUnicodeString(&ntPath, Path);

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &ntPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    IO_STATUS_BLOCK iosb = { 0 };
    HANDLE hFile = NULL;

    NTSTATUS status = ZwCreateFile(
        &hFile,
        DELETE | SYNCHRONIZE,
        &objAttr,
        &iosb,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );
    if (!NT_SUCCESS(status)) {
        return status;
    }

    FILE_DISPOSITION_INFORMATION disposition = { 0 };
    disposition.DeleteFile = TRUE;

    status = ZwSetInformationFile(
        hFile, &iosb,
        &disposition, sizeof(disposition),
        FileDispositionInformation
    );

    ZwClose(hFile);
    return status;
}
