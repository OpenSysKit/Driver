#include <ntifs.h>  // PsLookupProcessByProcessId 在这里声明
#include "driver.h"

// ========== PPL 相关定义 ==========

// EPROCESS.Protection 字段结构（Win8.1+）
typedef union _PS_PROTECTION {
    UCHAR Level;
    struct {
        UCHAR Type   : 3; // PS_PROTECTED_TYPE
        UCHAR Audit  : 1;
        UCHAR Signer : 4; // PS_PROTECTED_SIGNER
    };
} PS_PROTECTION;

// PS_PROTECTED_TYPE
#define PsProtectedTypeNone             0
#define PsProtectedTypeProtectedLight   1
#define PsProtectedTypeProtected        2

// PS_PROTECTED_SIGNER（常用值）
#define PsProtectedSignerNone           0
#define PsProtectedSignerAuthenticode   1
#define PsProtectedSignerCodeGen        2
#define PsProtectedSignerAntimalware    3
#define PsProtectedSignerLsa            4
#define PsProtectedSignerWindows        5
#define PsProtectedSignerWinTcb         6
#define PsProtectedSignerWinSystem      7
#define PsProtectedSignerApp            8

// 我们使用 PPL-Antimalware，兼容性好且权限足够
// Type=PsProtectedTypeProtectedLight, Signer=PsProtectedSignerAntimalware
#define PPL_LEVEL_ANTIMALWARE \
    ((PsProtectedSignerAntimalware << 4) | PsProtectedTypeProtectedLight)

// ========== 动态查找 EPROCESS.Protection 偏移 ==========
//
// Protection 字段在不同 Windows 版本偏移不同：
//   Win8.1  : 0x648
//   Win10 早期: 0x6B8 ~ 0x6C8（随补丁变化）
//   Win10 21H2+: 常见 0x87A
//   Win11   : 0x87A 或更高
//
// 策略：以 System 进程（PID=4）为已知样本，
// 在 EPROCESS 中搜索已知的 Protection 值（System 进程为 PsProtectedTypeProtected + PsProtectedSignerWinSystem）
// 来定位偏移。
//
// System 进程 Protection.Level = (WinSystem<<4)|Protected = (7<<4)|2 = 0x72
//
#define SYSTEM_PROTECTION_LEVEL 0x72  // WinSystem + Protected

static ULONG g_ProtectionOffset = 0;

static NTSTATUS FindProtectionOffset()
{
    PEPROCESS systemProcess = PsInitialSystemProcess;
    if (!systemProcess) return STATUS_UNSUCCESSFUL;

    PUCHAR base = (PUCHAR)systemProcess;

    // 搜索范围：0x300 ~ 0xC00（覆盖已知所有版本）
    for (ULONG offset = 0x300; offset < 0xC00; offset++) {
        if (base[offset] == SYSTEM_PROTECTION_LEVEL) {
            // 额外验证：前后字节应符合 EPROCESS 对齐特征
            // Protection 通常紧跟在 SignatureLevel（也是1字节）之后
            // SignatureLevel for System 通常非零
            if (base[offset - 1] != 0x00) {
                g_ProtectionOffset = offset;
                DbgPrint("[OpenSysKit] EPROCESS.Protection offset: 0x%X\n", offset);
                return STATUS_SUCCESS;
            }
        }
    }

    DbgPrint("[OpenSysKit] EPROCESS.Protection offset NOT found\n");
    return STATUS_NOT_FOUND;
}

// ========== 读写单个进程的 Protection 字段 ==========

static PS_PROTECTION ReadProtection(PEPROCESS process)
{
    PS_PROTECTION prot = { 0 };
    if (g_ProtectionOffset == 0) return prot;
    prot.Level = *((PUCHAR)process + g_ProtectionOffset);
    return prot;
}

static void WriteProtection(PEPROCESS process, PS_PROTECTION prot)
{
    if (g_ProtectionOffset == 0) return;
    *((PUCHAR)process + g_ProtectionOffset) = prot.Level;
}

// ========== 保护表管理 ==========
//
// 每个被保护的 PID 保存：PID、原始 Protection 值（用于恢复）
//

static NTSTATUS AddProtectedEntry(ULONG pid, UCHAR originalLevel)
{
    if (g_DriverContext.ProtectedPidCount >= MAX_PROTECTED_PIDS) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    ULONG i = g_DriverContext.ProtectedPidCount;
    g_DriverContext.ProtectedPids[i]          = pid;
    g_DriverContext.OriginalProtection[i]     = originalLevel;
    g_DriverContext.ProtectedPidCount++;
    return STATUS_SUCCESS;
}

static BOOLEAN RemoveProtectedEntry(ULONG pid, PUCHAR outOriginalLevel)
{
    for (ULONG i = 0; i < g_DriverContext.ProtectedPidCount; i++) {
        if (g_DriverContext.ProtectedPids[i] == pid) {
            if (outOriginalLevel) {
                *outOriginalLevel = g_DriverContext.OriginalProtection[i];
            }
            // 移除：用末尾元素填充
            ULONG last = g_DriverContext.ProtectedPidCount - 1;
            g_DriverContext.ProtectedPids[i]      = g_DriverContext.ProtectedPids[last];
            g_DriverContext.OriginalProtection[i] = g_DriverContext.OriginalProtection[last];
            g_DriverContext.ProtectedPidCount--;
            return TRUE;
        }
    }
    return FALSE;
}

// ========== 公开接口 ==========

NTSTATUS InitProtect()
{
    return FindProtectionOffset();
}

NTSTATUS ProcessProtect(ULONG ProcessId)
{
    if (g_ProtectionOffset == 0) return STATUS_UNSUCCESSFUL;
    if (ProcessId == 0 || ProcessId == 4) return STATUS_ACCESS_DENIED;

    PEPROCESS process = nullptr;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status)) return status;

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_DriverContext.ProtectLock, &oldIrql);

    // 检查是否已在保护列表中
    BOOLEAN alreadyProtected = FALSE;
    for (ULONG i = 0; i < g_DriverContext.ProtectedPidCount; i++) {
        if (g_DriverContext.ProtectedPids[i] == ProcessId) {
            alreadyProtected = TRUE;
            break;
        }
    }

    if (!alreadyProtected) {
        PS_PROTECTION original = ReadProtection(process);

        // 写入 PPL-Antimalware
        PS_PROTECTION ppl = { 0 };
        ppl.Level = PPL_LEVEL_ANTIMALWARE;
        WriteProtection(process, ppl);

        status = AddProtectedEntry(ProcessId, original.Level);

        DbgPrint("[OpenSysKit] ProcessProtect PID=%lu: 0x%02X -> 0x%02X\n",
            ProcessId, original.Level, ppl.Level);
    }

    KeReleaseSpinLock(&g_DriverContext.ProtectLock, oldIrql);
    ObDereferenceObject(process);
    return status;
}

NTSTATUS ProcessUnprotect(ULONG ProcessId)
{
    if (g_ProtectionOffset == 0) return STATUS_UNSUCCESSFUL;

    PEPROCESS process = nullptr;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status)) return status;

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_DriverContext.ProtectLock, &oldIrql);

    UCHAR originalLevel = 0;
    BOOLEAN found = RemoveProtectedEntry(ProcessId, &originalLevel);

    if (found) {
        // 恢复原始 Protection 值
        PS_PROTECTION prot = { 0 };
        prot.Level = originalLevel;
        WriteProtection(process, prot);

        DbgPrint("[OpenSysKit] ProcessUnprotect PID=%lu: restored 0x%02X\n",
            ProcessId, originalLevel);
        status = STATUS_SUCCESS;
    } else {
        status = STATUS_NOT_FOUND;
    }

    KeReleaseSpinLock(&g_DriverContext.ProtectLock, oldIrql);
    ObDereferenceObject(process);
    return status;
}

// 驱动卸载时恢复所有被保护进程，防止蓝屏
VOID CleanupProtect()
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_DriverContext.ProtectLock, &oldIrql);

    for (ULONG i = 0; i < g_DriverContext.ProtectedPidCount; i++) {
        ULONG pid = g_DriverContext.ProtectedPids[i];
        UCHAR originalLevel = g_DriverContext.OriginalProtection[i];

        PEPROCESS process = nullptr;
        // 注意：此处在 SpinLock 持有时调用 PsLookupProcessByProcessId 是不安全的
        // 先收集再释放锁处理
        UNREFERENCED_PARAMETER(pid);
        UNREFERENCED_PARAMETER(originalLevel);
    }

    // 正确做法：先把列表快照出来，释放锁再逐个恢复
    ULONG count = g_DriverContext.ProtectedPidCount;
    ULONG pids[MAX_PROTECTED_PIDS];
    UCHAR levels[MAX_PROTECTED_PIDS];
    RtlCopyMemory(pids,   g_DriverContext.ProtectedPids,      count * sizeof(ULONG));
    RtlCopyMemory(levels, g_DriverContext.OriginalProtection,  count * sizeof(UCHAR));

    g_DriverContext.ProtectedPidCount = 0;

    KeReleaseSpinLock(&g_DriverContext.ProtectLock, oldIrql);

    for (ULONG i = 0; i < count; i++) {
        PEPROCESS process = nullptr;
        NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pids[i], &process);
        if (NT_SUCCESS(status)) {
            PS_PROTECTION prot = { 0 };
            prot.Level = levels[i];
            WriteProtection(process, prot);
            ObDereferenceObject(process);
            DbgPrint("[OpenSysKit] CleanupProtect PID=%lu restored 0x%02X\n", pids[i], levels[i]);
        }
    }
}