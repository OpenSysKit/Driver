#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x0A000008
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include <ntifs.h>
#include "protect.h"

// ========== PPL 相关定义 ==========

typedef struct _PS_PROTECTION {
    union {
        UCHAR Level;
        struct {
            UCHAR Type   : 3;
            UCHAR Audit  : 1;
            UCHAR Signer : 4;
        };
    };
} PS_PROTECTION, *PPS_PROTECTION;

#define PsProtectedTypeNone             0
#define PsProtectedTypeProtectedLight   1
#define PsProtectedTypeProtected        2

#define PsProtectedSignerNone           0
#define PsProtectedSignerAuthenticode   1
#define PsProtectedSignerCodeGen        2
#define PsProtectedSignerAntimalware    3
#define PsProtectedSignerLsa            4
#define PsProtectedSignerWindows        5
#define PsProtectedSignerWinTcb         6
#define PsProtectedSignerWinSystem      7
#define PsProtectedSignerApp            8

// PPL-Antimalware：兼容性好且权限足够
#define PPL_LEVEL_ANTIMALWARE \
    ((PsProtectedSignerAntimalware << 4) | PsProtectedTypeProtectedLight)

// ========== 动态查找 EPROCESS.Protection 偏移 ==========
//
// 以 System 进程（PID=4）为已知样本扫描偏移。
// EPROCESS 中三个字段紧邻排列（Win10/Win11 均如此）：
//   [offset-2] SignatureLevel        : 0x3C（WinSystem）
//   [offset-1] SectionSignatureLevel : 可能为 0
//   [offset]   Protection.Level      : 0x72（WinSystem + Protected）
//
// 只用 SignatureLevel + Protection 两字节联合验证，
// SectionSignatureLevel 在某些版本上为 0，不参与匹配。
//

#define SYSTEM_PROTECTION_LEVEL  0x72
#define SYSTEM_SIGNATURE_LEVEL   0x3C

static ULONG g_ProtectionOffset = 0;

static NTSTATUS FindProtectionOffset()
{
    PEPROCESS systemProcess = PsInitialSystemProcess;
    if (!systemProcess) return STATUS_UNSUCCESSFUL;

    PUCHAR base = (PUCHAR)systemProcess;

    // 扩大扫描范围到 0x1000，覆盖更多 Windows 版本
    for (ULONG offset = 0x302; offset < 0x1000; offset++) {
        if (base[offset]   != SYSTEM_PROTECTION_LEVEL) continue;
        if (base[offset-2] != SYSTEM_SIGNATURE_LEVEL)  continue;

        g_ProtectionOffset = offset;
        DbgPrint("[OpenSysKit] EPROCESS.Protection offset: 0x%X "
                 "(sigLevel=0x%02X sectSigLevel=0x%02X)\n",
                 offset, base[offset-2], base[offset-1]);
        return STATUS_SUCCESS;
    }

    DbgPrint("[OpenSysKit] EPROCESS.Protection offset NOT found\n");
    return STATUS_NOT_FOUND;
}

// ========== 读写 Protection 字段 ==========

static PS_PROTECTION ReadProtection(PEPROCESS process)
{
    PS_PROTECTION prot = { 0 };
    if (g_ProtectionOffset == 0) return prot;
    
    __try {
        prot.Level = *((PUCHAR)process + g_ProtectionOffset);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[OpenSysKit] ReadProtection: 内存访问异常\n");
        prot.Level = 0;
    }
    return prot;
}

static VOID WriteProtection(PEPROCESS process, PS_PROTECTION prot)
{
    if (g_ProtectionOffset == 0) return;
    
    __try {
        *((PUCHAR)process + g_ProtectionOffset) = prot.Level;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[OpenSysKit] WriteProtection: 内存访问异常\n");
    }
}

// ========== 保护表管理 ==========
//
// 记录每个被保护 PID 的原始 Protection.Level，用于恢复。
//

static NTSTATUS AddProtectedEntry(ULONG pid, UCHAR originalLevel)
{
    if (g_DriverContext.ProtectedPidCount >= MAX_PROTECTED_PIDS)
        return STATUS_INSUFFICIENT_RESOURCES;

    ULONG i = g_DriverContext.ProtectedPidCount;
    g_DriverContext.ProtectedPids[i]      = pid;
    g_DriverContext.OriginalProtection[i] = originalLevel;
    g_DriverContext.ProtectedPidCount++;
    return STATUS_SUCCESS;
}

static BOOLEAN RemoveProtectedEntry(ULONG pid, PUCHAR outOriginalLevel)
{
    for (ULONG i = 0; i < g_DriverContext.ProtectedPidCount; i++) {
        if (g_DriverContext.ProtectedPids[i] != pid) continue;

        if (outOriginalLevel)
            *outOriginalLevel = g_DriverContext.OriginalProtection[i];

        // 用末尾元素填充空位
        ULONG last = g_DriverContext.ProtectedPidCount - 1;
        g_DriverContext.ProtectedPids[i]      = g_DriverContext.ProtectedPids[last];
        g_DriverContext.OriginalProtection[i] = g_DriverContext.OriginalProtection[last];
        g_DriverContext.ProtectedPidCount--;
        return TRUE;
    }
    return FALSE;
}

// ========== 保护等级验证 ==========

static BOOLEAN IsValidProtectionLevel(UCHAR level)
{
    if (level == 0) return TRUE; // 允许设置为无保护
    
    UCHAR type = level & 0x07;   // 低 3 位
    UCHAR signer = level >> 4;   // 高 4 位
    
    // Type 必须为 0, 1, 2
    if (type > 2) return FALSE;
    
    // Signer 必须为 0-8
    if (signer > 8) return FALSE;
    
    return TRUE;
}

// ========== 公开接口 ==========

NTSTATUS InitProtect()
{
    return FindProtectionOffset();
}

// 兼容旧接口：使用默认的 Antimalware-Light 保护
NTSTATUS ProcessProtect(ULONG ProcessId)
{
    return ProcessSetProtectLevel(ProcessId, PPL_LEVEL_ANTIMALWARE);
}

// 设置指定的保护等级
NTSTATUS ProcessSetProtectLevel(ULONG ProcessId, UCHAR ProtectionLevel)
{
    if (g_ProtectionOffset == 0) return STATUS_UNSUCCESSFUL;
    if (ProcessId == 0 || ProcessId == 4) return STATUS_ACCESS_DENIED;

    // 在获取锁之前先查找进程
    PEPROCESS process = nullptr;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status)) return status;

    // 0 视为取消保护（恢复原始值）
    if (ProtectionLevel == 0) {
        KIRQL oldIrql;
        KeAcquireSpinLock(&g_DriverContext.ProtectLock, &oldIrql);

        UCHAR originalLevel = 0;
        BOOLEAN found = RemoveProtectedEntry(ProcessId, &originalLevel);

        KeReleaseSpinLock(&g_DriverContext.ProtectLock, oldIrql);

        if (found) {
            PS_PROTECTION prot = { 0 };
            prot.Level = originalLevel;
            WriteProtection(process, prot);
            DbgPrint("[OpenSysKit] ProcessSetProtectLevel PID=%lu: restore 0x%02X\n", ProcessId, originalLevel);
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_NOT_FOUND;
        }

        ObDereferenceObject(process);
        return status;
    }

    // 验证保护等级的合法性
    if (!IsValidProtectionLevel(ProtectionLevel)) {
        DbgPrint("[OpenSysKit] ProcessSetProtectLevel: 无效的保护等级 0x%02X\n", ProtectionLevel);
        ObDereferenceObject(process);
        return STATUS_INVALID_PARAMETER;
    }

    // 读取原始保护级别（在锁外进行）
    PS_PROTECTION original = ReadProtection(process);

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_DriverContext.ProtectLock, &oldIrql);

    // 检查是否已保护
    BOOLEAN alreadyProtected = FALSE;
    for (ULONG i = 0; i < g_DriverContext.ProtectedPidCount; i++) {
        if (g_DriverContext.ProtectedPids[i] == ProcessId) {
            alreadyProtected = TRUE;
            break;
        }
    }

    if (!alreadyProtected) {
        // 首次保护，加入保护表
        status = AddProtectedEntry(ProcessId, original.Level);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[OpenSysKit] ProcessSetProtectLevel PID=%lu: table full\n", ProcessId);
            KeReleaseSpinLock(&g_DriverContext.ProtectLock, oldIrql);
            ObDereferenceObject(process);
            return status;
        }
    }

    // 设置新的保护等级
    PS_PROTECTION ppl = { 0 };
    ppl.Level = ProtectionLevel;
    WriteProtection(process, ppl);
    DbgPrint("[OpenSysKit] ProcessSetProtectLevel PID=%lu: 0x%02X -> 0x%02X\n",
        ProcessId, original.Level, ppl.Level);

    KeReleaseSpinLock(&g_DriverContext.ProtectLock, oldIrql);
    ObDereferenceObject(process);
    return STATUS_SUCCESS;
}

NTSTATUS ProcessUnprotect(ULONG ProcessId)
{
    if (g_ProtectionOffset == 0) return STATUS_UNSUCCESSFUL;

    // 在获取锁之前先查找进程
    PEPROCESS process = nullptr;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status)) return status;

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_DriverContext.ProtectLock, &oldIrql);

    UCHAR originalLevel = 0;
    BOOLEAN found = RemoveProtectedEntry(ProcessId, &originalLevel);

    KeReleaseSpinLock(&g_DriverContext.ProtectLock, oldIrql);

    if (found) {
        PS_PROTECTION prot = { 0 };
        prot.Level = originalLevel;
        WriteProtection(process, prot);
        DbgPrint("[OpenSysKit] ProcessUnprotect PID=%lu: restored 0x%02X\n",
            ProcessId, originalLevel);
        status = STATUS_SUCCESS;
    } else {
        status = STATUS_NOT_FOUND;
    }

    ObDereferenceObject(process);
    return status;
}

// 快照保护表后释放锁，再逐个恢复 Protection，避免在 SpinLock 内调用可分页函数
VOID CleanupProtect()
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_DriverContext.ProtectLock, &oldIrql);

    ULONG count = g_DriverContext.ProtectedPidCount;
    ULONG pids[MAX_PROTECTED_PIDS];
    UCHAR levels[MAX_PROTECTED_PIDS];
    RtlCopyMemory(pids,   g_DriverContext.ProtectedPids,      count * sizeof(ULONG));
    RtlCopyMemory(levels, g_DriverContext.OriginalProtection,  count * sizeof(UCHAR));
    g_DriverContext.ProtectedPidCount = 0;

    KeReleaseSpinLock(&g_DriverContext.ProtectLock, oldIrql);

    for (ULONG i = 0; i < count; i++) {
        PEPROCESS process = nullptr;
        if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pids[i], &process))) {
            PS_PROTECTION prot = { 0 };
            prot.Level = levels[i];
            WriteProtection(process, prot);
            ObDereferenceObject(process);
            DbgPrint("[OpenSysKit] CleanupProtect PID=%lu restored 0x%02X\n", pids[i], levels[i]);
        }
    }
}
