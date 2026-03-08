#include <ntifs.h>
#include "token.h"

//
// Token 替换提权原理：
//   EPROCESS.Token 是 EX_FAST_REF，指向进程访问令牌。
//   替换该字段即可原地改变进程权限，无需重启。
//
// 三种级别实现方式：
//
//   SYSTEM (Level=1)：
//     直接复制 PsInitialSystemProcess（PID=4）的 Token。
//     最简单，不涉及用户态对象。
//
//   Admin (Level=0)：
//     找到任意一个以管理员身份运行的进程（winlogon.exe / lsass.exe），
//     复制其 Token。这些进程在 Session 0 以高完整性 + Administrators 组运行。
//     优先找 winlogon，找不到找 lsass。
//
//   TrustedInstaller (Level=2)：
//     TrustedInstaller 权限来自 NT SERVICE\TrustedInstaller Token。
//     该服务进程名为 TrustedInstaller.exe，通过 ZwQuerySystemInformation
//     遍历进程列表找到它，复制其 Token。
//     若服务未运行则返回 STATUS_NOT_FOUND。
//
// Token 字段偏移：
//   动态扫描 PsReferencePrimaryToken 内 MOV RAX,[RCX+imm32]（48 8B 81）提取。
//   失败则按 Build 号回退：Build<=19044 用 0x358，否则用 0x4B8。
//

// ========== 系统进程信息结构（ZwQuerySystemInformation Class=5）==========

typedef struct _SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG         WaitTime;
    PVOID         StartAddress;
    CLIENT_ID     ClientId;
    KPRIORITY     Priority;
    LONG          BasePriority;
    ULONG         ContextSwitches;
    ULONG         ThreadState;
    ULONG         WaitReason;
} SYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFO {
    ULONG                    NextEntryOffset;
    ULONG                    NumberOfThreads;
    LARGE_INTEGER            Reserved[3];
    LARGE_INTEGER            CreateTime;
    LARGE_INTEGER            UserTime;
    LARGE_INTEGER            KernelTime;
    UNICODE_STRING           ImageName;
    KPRIORITY                BasePriority;
    HANDLE                   UniqueProcessId;
    HANDLE                   InheritedFromUniqueProcessId;
    ULONG                    HandleCount;
    ULONG                    SessionId;
    ULONG_PTR                PageDirectoryBase;
    SIZE_T                   PeakVirtualSize;
    SIZE_T                   VirtualSize;
    ULONG                    PageFaultCount;
    SIZE_T                   PeakWorkingSetSize;
    SIZE_T                   WorkingSetSize;
} SYSTEM_PROCESS_INFO, *PSYSTEM_PROCESS_INFO;

extern "C" NTSTATUS NTAPI ZwQuerySystemInformation(
    ULONG  SystemInformationClass,
    PVOID  SystemInformation,
    ULONG  SystemInformationLength,
    PULONG ReturnLength
);

#define SystemProcessInformation 5

// ========== Token 字段偏移 ==========

static ULONG g_TokenOffset = 0;

static ULONG FindTokenOffsetDynamic()
{
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"PsReferencePrimaryToken");
    PUCHAR func = (PUCHAR)MmGetSystemRoutineAddress(&name);
    if (!func) return 0;

    for (ULONG i = 0; i < 32; i++) {
        // 48 8B 81 xx xx 00 00  =>  mov rax, [rcx + offset]
        if (func[i] == 0x48 && func[i+1] == 0x8B && func[i+2] == 0x81) {
            ULONG offset = *(PULONG)(func + i + 3);
            if (offset >= 0x200 && offset <= 0x800) {
                DbgPrint("[OpenSysKit] [Token] dynamic offset=0x%X\n", offset);
                return offset;
            }
        }
    }
    return 0;
}

static ULONG FindTokenOffsetByVersion()
{
    RTL_OSVERSIONINFOW osInfo = { sizeof(osInfo) };
    RtlGetVersion(&osInfo);
    DbgPrint("[OpenSysKit] [Token] Build=%lu, using static offset\n", osInfo.dwBuildNumber);
    return (osInfo.dwBuildNumber <= 19044) ? 0x358u : 0x4B8u;
}

static VOID EnsureTokenOffset()
{
    if (g_TokenOffset != 0) return;
    g_TokenOffset = FindTokenOffsetDynamic();
    if (g_TokenOffset == 0)
        g_TokenOffset = FindTokenOffsetByVersion();
    DbgPrint("[OpenSysKit] [Token] Token offset=0x%X\n", g_TokenOffset);
}

static ULONG_PTR ReadToken(PEPROCESS process)
{
    return *(PULONG_PTR)((PUCHAR)process + g_TokenOffset);
}

static VOID WriteToken(PEPROCESS process, ULONG_PTR token)
{
    *(PULONG_PTR)((PUCHAR)process + g_TokenOffset) = token;
}

// ========== 按进程名查找 EPROCESS ==========
//
// 在系统进程列表中匹配 ImageName，返回第一个匹配项的 EPROCESS。
// 调用者负责 ObDereferenceObject。
//

static NTSTATUS FindProcessByName(
    _In_  PCWSTR   targetName,
    _Out_ PEPROCESS* outProcess)
{
    *outProcess = nullptr;

    ULONG bufSize = 0;
    NTSTATUS status = ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &bufSize);
    if (status != STATUS_INFO_LENGTH_MISMATCH) return status;

    bufSize += 4096;
    PVOID buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufSize, 'koTk');
    if (!buf) return STATUS_INSUFFICIENT_RESOURCES;

    status = ZwQuerySystemInformation(SystemProcessInformation, buf, bufSize, &bufSize);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(buf, 'koTk');
        return status;
    }

    UNICODE_STRING target;
    RtlInitUnicodeString(&target, targetName);

    status = STATUS_NOT_FOUND;
    PSYSTEM_PROCESS_INFO entry = (PSYSTEM_PROCESS_INFO)buf;

    while (TRUE) {
        if (entry->ImageName.Buffer && entry->UniqueProcessId != 0) {
            if (RtlEqualUnicodeString(&entry->ImageName, &target, TRUE)) {
                PEPROCESS proc = nullptr;
                NTSTATUS s = PsLookupProcessByProcessId(entry->UniqueProcessId, &proc);
                if (NT_SUCCESS(s)) {
                    *outProcess = proc;
                    status = STATUS_SUCCESS;
                    break;
                }
            }
        }
        if (entry->NextEntryOffset == 0) break;
        entry = (PSYSTEM_PROCESS_INFO)((PUCHAR)entry + entry->NextEntryOffset);
    }

    ExFreePoolWithTag(buf, 'koTk');
    return status;
}

// ========== 各级别 Token 来源 ==========

// Level 1: SYSTEM — 直接用 PsInitialSystemProcess（PID=4）
static NTSTATUS GetSystemToken(_Out_ ULONG_PTR* token)
{
    PEPROCESS systemProc = nullptr;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)4, &systemProc);
    if (!NT_SUCCESS(status)) return status;
    *token = ReadToken(systemProc);
    ObDereferenceObject(systemProc);
    return STATUS_SUCCESS;
}

// Level 0: Admin — 找 winlogon.exe，找不到找 lsass.exe
// 这两个进程均以高完整性 + Administrators Token 运行
static NTSTATUS GetAdminToken(_Out_ ULONG_PTR* token)
{
    PEPROCESS proc = nullptr;
    NTSTATUS status = FindProcessByName(L"winlogon.exe", &proc);
    if (!NT_SUCCESS(status)) {
        status = FindProcessByName(L"lsass.exe", &proc);
    }
    if (!NT_SUCCESS(status)) {
        DbgPrint("[OpenSysKit] [Token] Admin: neither winlogon nor lsass found\n");
        return status;
    }
    *token = ReadToken(proc);
    ObDereferenceObject(proc);
    return STATUS_SUCCESS;
}

// Level 2: TrustedInstaller — 找 TrustedInstaller.exe
// 该服务按需启动，若未运行返回 STATUS_NOT_FOUND
static NTSTATUS GetTrustedInstallerToken(_Out_ ULONG_PTR* token)
{
    PEPROCESS proc = nullptr;
    NTSTATUS status = FindProcessByName(L"TrustedInstaller.exe", &proc);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[OpenSysKit] [Token] TrustedInstaller.exe not running\n");
        return status;
    }
    *token = ReadToken(proc);
    ObDereferenceObject(proc);
    return STATUS_SUCCESS;
}

// ========== 公开接口 ==========

NTSTATUS ProcessElevate(ULONG ProcessId, ULONG Level)
{
    if (ProcessId == 0 || ProcessId == 4) {
        return STATUS_ACCESS_DENIED;
    }

    EnsureTokenOffset();
    if (g_TokenOffset == 0) {
        DbgPrint("[OpenSysKit] [Token] offset unknown\n");
        return STATUS_UNSUCCESSFUL;
    }

    // 获取来源 Token
    ULONG_PTR sourceToken = 0;
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    switch (Level) {
    case ELEVATE_LEVEL_ADMIN:
        DbgPrint("[OpenSysKit] [Token] PID=%lu -> Admin\n", ProcessId);
        status = GetAdminToken(&sourceToken);
        break;
    case ELEVATE_LEVEL_SYSTEM:
        DbgPrint("[OpenSysKit] [Token] PID=%lu -> SYSTEM\n", ProcessId);
        status = GetSystemToken(&sourceToken);
        break;
    case ELEVATE_LEVEL_TRUSTED_INSTALLER:
        DbgPrint("[OpenSysKit] [Token] PID=%lu -> TrustedInstaller\n", ProcessId);
        status = GetTrustedInstallerToken(&sourceToken);
        break;
    default:
        DbgPrint("[OpenSysKit] [Token] unknown Level=%lu\n", Level);
        return STATUS_INVALID_PARAMETER;
    }

    if (!NT_SUCCESS(status)) {
        DbgPrint("[OpenSysKit] [Token] failed to get source token: 0x%08X\n", status);
        return status;
    }

    // 获取目标进程，替换 Token
    PEPROCESS targetProcess = nullptr;
    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &targetProcess);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[OpenSysKit] [Token] lookup PID=%lu failed: 0x%08X\n", ProcessId, status);
        return status;
    }

    ULONG_PTR oldToken = ReadToken(targetProcess);
    WriteToken(targetProcess, sourceToken);

    DbgPrint("[OpenSysKit] [Token] PID=%lu elevated (Level=%lu): 0x%llX -> 0x%llX\n",
        ProcessId, Level, (ULONG64)oldToken, (ULONG64)sourceToken);

    ObDereferenceObject(targetProcess);
    return STATUS_SUCCESS;
}
