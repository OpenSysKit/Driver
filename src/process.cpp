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

// ========== PspTerminateProcess 动态解析 ==========
//
// 签名：NTSTATUS PspTerminateProcess(PEPROCESS Process, NTSTATUS ExitStatus)
//
typedef NTSTATUS(NTAPI* PFN_PSP_TERMINATE_PROCESS)(PEPROCESS Process, NTSTATUS ExitStatus);

static PFN_PSP_TERMINATE_PROCESS g_PspTerminateProcess = nullptr;

// ---------- 工具：验证地址是否在内核空间 ----------

static BOOLEAN IsKernelAddress(PVOID addr)
{
    return (ULONG_PTR)addr > (ULONG_PTR)0xFFFF000000000000ULL;
}

//
// 从函数 stub 中扫描 E8/E9 相对跳转，提取目标地址。
//
static PVOID ScanRelativeCall(PVOID funcBase, ULONG maxScan)
{
    PUCHAR p = (PUCHAR)funcBase;
    for (ULONG i = 0; i < maxScan; i++) {
        if (p[i] == 0xC3 || p[i] == 0xC2) break; // RET，停止
        if (p[i] == 0xE8 || p[i] == 0xE9) {
            LONG rel = *(PLONG)(p + i + 1);
            PVOID target = p + i + 5 + rel;
            if (IsKernelAddress(target)) {
                return target;
            }
        }
    }
    return nullptr;
}

// ---------- 策略 1：PsTerminateProcess stub（Win8.1+）----------
//
// PsTerminateProcess 是公开导出的薄包装，内部直接 jmp/call PspTerminateProcess。
//
static PFN_PSP_TERMINATE_PROCESS ResolveViaPsTerminateProcess()
{
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"PsTerminateProcess");
    PVOID stub = MmGetSystemRoutineAddress(&name);
    if (!stub) return nullptr;

    PVOID target = ScanRelativeCall(stub, 32);
    if (target) {
        DbgPrint("[OpenSysKit] [Resolve#1] PsTerminateProcess -> %p\n", target);
    }
    return (PFN_PSP_TERMINATE_PROCESS)target;
}

// ---------- 策略 2：ZwTerminateProcess 调用链扫描（Win7+）----------
//
// NtTerminateProcess 内部会 call PspTerminateProcess。
// ZwTerminateProcess 在内核中是 syscall stub，扫描其调用链中
// 最后一个合理的 E8 目标（通常就是 PspTerminateProcess）。
//
static PFN_PSP_TERMINATE_PROCESS ResolveViaZwTerminateProcess()
{
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"ZwTerminateProcess");
    PVOID zwStub = MmGetSystemRoutineAddress(&name);
    if (!zwStub) return nullptr;

    PUCHAR p = (PUCHAR)zwStub;
    PVOID lastCandidate = nullptr;

    for (ULONG i = 0; i < 256; i++) {
        if (p[i] == 0xC3 || p[i] == 0xC2) break; // RET
        if (p[i] == 0xE8) {
            LONG rel = *(PLONG)(p + i + 1);
            PVOID target = p + i + 5 + rel;
            if (IsKernelAddress(target)) {
                lastCandidate = target; // 持续更新，取最后一个
            }
        }
    }

    if (lastCandidate) {
        DbgPrint("[OpenSysKit] [Resolve#2] ZwTerminateProcess scan -> %p\n", lastCandidate);
    }
    return (PFN_PSP_TERMINATE_PROCESS)lastCandidate;
}

// ---------- 策略 3：PspTerminateAllThreads 附近导出锚定（Win7/8）----------
//
// 部分旧版 Windows 上 PsTerminateProcess 未导出，但可以从
// PsTerminateSystemThread（公开导出）附近找到 PspTerminateProcess。
// PsTerminateSystemThread 内部会调用 PspTerminateProcess。
//
static PFN_PSP_TERMINATE_PROCESS ResolveViaPsTerminateSystemThread()
{
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"PsTerminateSystemThread");
    PVOID stub = MmGetSystemRoutineAddress(&name);
    if (!stub) return nullptr;

    // PsTerminateSystemThread 比较复杂，扫描前 128 字节，
    // 收集所有候选，取第一个（PspTerminateProcess 通常较早调用）。
    PUCHAR p = (PUCHAR)stub;
    for (ULONG i = 0; i < 128; i++) {
        if (p[i] == 0xC3 || p[i] == 0xC2) break;
        if (p[i] == 0xE8) {
            LONG rel = *(PLONG)(p + i + 1);
            PVOID target = p + i + 5 + rel;
            if (IsKernelAddress(target)) {
                DbgPrint("[OpenSysKit] [Resolve#3] PsTerminateSystemThread -> %p\n", target);
                return (PFN_PSP_TERMINATE_PROCESS)target;
            }
        }
    }
    return nullptr;
}

// ---------- 策略 4：特征码扫描兜底（Win7~Win11 x64）----------
//
// 以 ZwTerminateProcess 为锚点，在 ±512KB 范围内扫描
// PspTerminateProcess 的函数 prologue 特征。
//
// Win7~Win11 x64 PspTerminateProcess 常见 prologue：
//   48 89 5C 24 ?? 48 89 6C 24 ?? [48 89 74 24 ??] 57 41 5?
//
static PFN_PSP_TERMINATE_PROCESS ResolveViaSignatureScan()
{
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"ZwTerminateProcess");
    PVOID anchor = MmGetSystemRoutineAddress(&name);
    if (!anchor) return nullptr;

    // 扫描范围：锚点前后 512KB
    const ULONG scanRange = 512 * 1024;
    PUCHAR base = (PUCHAR)anchor - scanRange;
    PUCHAR end  = (PUCHAR)anchor + scanRange;

    if (!IsKernelAddress(base)) base = (PUCHAR)anchor;

    for (PUCHAR p = base; p < end - 32; p++) {
        // 特征：mov [rsp+??],rbx  mov [rsp+??],rbp  57(push rdi) 或 41 5?(push r1?)
        if (p[0] == 0x48 && p[1] == 0x89 && p[2] == 0x5C && p[3] == 0x24 &&
            p[5] == 0x48 && p[6] == 0x89 && p[7] == 0x6C && p[8] == 0x24)
        {
            // 前一字节应是 CC/90（padding）或 C3（ret of previous func）
            if (p > base) {
                UCHAR prev = *(p - 1);
                if (prev != 0xCC && prev != 0x90 && prev != 0xC3) continue;
            }

            // 后续应有 push 指令（57 或 41 5x 系列），进一步确认是函数头
            UCHAR after = p[10];
            if (after != 0x57 && (after & 0xF8) != 0x40) continue;

            DbgPrint("[OpenSysKit] [Resolve#4] Signature scan candidate: %p\n", p);
            return (PFN_PSP_TERMINATE_PROCESS)p;
        }
    }
    return nullptr;
}

// ---------- 主入口：依次尝试四种策略 ----------

VOID ResolvePspTerminateProcess()
{
    // 策略 1：PsTerminateProcess stub（Win8.1+，最可靠）
    g_PspTerminateProcess = ResolveViaPsTerminateProcess();
    if (g_PspTerminateProcess) {
        DbgPrint("[OpenSysKit] PspTerminateProcess OK (Strategy 1): %p\n", g_PspTerminateProcess);
        return;
    }

    // 策略 2：ZwTerminateProcess 调用链（Win7+）
    g_PspTerminateProcess = ResolveViaZwTerminateProcess();
    if (g_PspTerminateProcess) {
        DbgPrint("[OpenSysKit] PspTerminateProcess OK (Strategy 2): %p\n", g_PspTerminateProcess);
        return;
    }

    // 策略 3：PsTerminateSystemThread 调用链（Win7/8 备选）
    g_PspTerminateProcess = ResolveViaPsTerminateSystemThread();
    if (g_PspTerminateProcess) {
        DbgPrint("[OpenSysKit] PspTerminateProcess OK (Strategy 3): %p\n", g_PspTerminateProcess);
        return;
    }

    // 策略 4：特征码扫描（最后兜底）
    g_PspTerminateProcess = ResolveViaSignatureScan();
    if (g_PspTerminateProcess) {
        DbgPrint("[OpenSysKit] PspTerminateProcess OK (Strategy 4 sig-scan): %p\n", g_PspTerminateProcess);
        return;
    }

    DbgPrint("[OpenSysKit] PspTerminateProcess NOT resolved, will fallback to ZwTerminateProcess\n");
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
    PVOID buffer = ExAllocatePoolWithTag(NonPagedPool, bufferSize, 'ksyS');
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

NTSTATUS ProcessKill(ULONG ProcessId)
{
    if (ProcessId == 0 || ProcessId == 4) {
        return STATUS_ACCESS_DENIED;
    }

    // --- 路径 1：PspTerminateProcess（直接传 PEPROCESS，绕过句柄层）---
    if (g_PspTerminateProcess) {
        PEPROCESS process = nullptr;
        NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
        if (NT_SUCCESS(status)) {
            // 检查 BreakOnTermination，防止对受保护进程调用导致蓝屏
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
                    return STATUS_ACCESS_DENIED;
                }
            }

            status = g_PspTerminateProcess(process, STATUS_SUCCESS);
            ObDereferenceObject(process);

            if (NT_SUCCESS(status)) {
                DbgPrint("[OpenSysKit] ProcessKill PID=%lu via PspTerminateProcess OK\n", ProcessId);
                return STATUS_SUCCESS;
            }
            DbgPrint("[OpenSysKit] PspTerminateProcess failed (0x%08X), falling back to Zw\n", status);
        }
    }

    // --- 路径 2：ZwTerminateProcess 回退 ---
    HANDLE hProcess = NULL;
    NTSTATUS status = OpenProcessById(
        ProcessId, &hProcess,
        PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION
    );
    if (!NT_SUCCESS(status)) {
        return status;
    }

    ULONG breakOnTermination = 0;
    status = ZwQueryInformationProcess(
        hProcess, ProcessBreakOnTermination,
        &breakOnTermination, sizeof(breakOnTermination), NULL
    );
    if (!NT_SUCCESS(status)) {
        ZwClose(hProcess);
        return status;
    }
    if (breakOnTermination != 0) {
        ZwClose(hProcess);
        return STATUS_ACCESS_DENIED;
    }

    status = ZwTerminateProcess(hProcess, STATUS_SUCCESS);
    DbgPrint("[OpenSysKit] ProcessKill PID=%lu via ZwTerminateProcess: 0x%08X\n", ProcessId, status);
    ZwClose(hProcess);
    return status;
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