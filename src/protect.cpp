#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x0A000008
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include <ntifs.h>
#include "driver.h"

// ========== PPL 相关定义 ==========

typedef union _PS_PROTECTION {
    UCHAR Level;
    struct {
        UCHAR Type   : 3;
        UCHAR Audit  : 1;
        UCHAR Signer : 4;
    };
} PS_PROTECTION;

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
//   [offset-1] SectionSignatureLevel : 非零
//   [offset]   Protection.Level      : 0x72（WinSystem + Protected）
//

#define SYSTEM_PROTECTION_LEVEL  0x72
#define SYSTEM_SIGNATURE_LEVEL   0x3C

static ULONG g_ProtectionOffset = 0;

static NTSTATUS FindProtectionOffset()
{
    PEPROCESS systemProcess = PsInitialSystemProcess;
    if (!systemProcess) return STATUS_UNSUCCESSFUL;

    PUCHAR base = (PUCHAR)systemProcess;

    for (ULONG offset = 0x302; offset < 0xC00; offset++) {
        if (base[offset]   != SYSTEM_PROTECTION_LEVEL) continue;
        if (base[offset-2] != SYSTEM_SIGNATURE_LEVEL)  continue;
        if (base[offset-1] == 0x00)                    continue;

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
    prot.Level = *((PUCHAR)process + g_ProtectionOffset);
    return prot;
}

static VOID WriteProtection(PEPROCESS process, PS_PROTECTION prot)
{
    if (g_ProtectionOffset == 0) return;
    *((PUCHAR)process + g_ProtectionOffset) = prot.Level;
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

    // 已保护则幂等返回
    for (ULONG i = 0; i < g_DriverContext.ProtectedPidCount; i++) {
        if (g_DriverContext.ProtectedPids[i] == ProcessId) {
            KeReleaseSpinLock(&g_DriverContext.ProtectLock, oldIrql);
            ObDereferenceObject(process);
            return STATUS_SUCCESS;
        }
    }

    // 先加入保护表，确认有位置后再写 PPL，
    // 防止写了 PPL 却因表满无法记录导致无法恢复
    PS_PROTECTION original = ReadProtection(process);
    status = AddProtectedEntry(ProcessId, original.Level);
    if (NT_SUCCESS(status)) {
        PS_PROTECTION ppl = { 0 };
        ppl.Level = PPL_LEVEL_ANTIMALWARE;
        WriteProtection(process, ppl);
        DbgPrint("[OpenSysKit] ProcessProtect PID=%lu: 0x%02X -> 0x%02X\n",
            ProcessId, original.Level, ppl.Level);
    } else {
        DbgPrint("[OpenSysKit] ProcessProtect PID=%lu: table full\n", ProcessId);
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
