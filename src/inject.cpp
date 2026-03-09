#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x0A000008
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include <ntifs.h>
#include "inject.h"

// ========== 内核 APC DLL 注入 ==========
//
// 原理：
//   1. 附加到目标进程地址空间，在其中分配内存写入 DLL 路径字符串
//   2. 从目标进程 PEB.Ldr 遍历模块，找到 KERNELBASE.dll，
//      解析其导出表定位 LoadLibraryW 地址
//   3. KeInitializeApc + KeInsertQueueApc 向目标进程的一个用户态线程
//      排队用户模式 APC，APC 例程指向 LoadLibraryW，参数为路径缓冲区地址
//   4. 目标线程下次进入可报警等待（alertable wait）时 APC 触发，DLL 加载
//
// 注意：注入是异步的，函数返回 STATUS_SUCCESS 只代表 APC 已入队，
//       不代表 DLL 已加载完成。
//

typedef PETHREAD (NTAPI* PFN_PS_GET_NEXT_PROCESS_THREAD)(
    _In_ PEPROCESS Process,
    _In_opt_ PETHREAD Thread
);

typedef VOID (NTAPI* POSK_NORMAL_ROUTINE)(
    _In_opt_ PVOID NormalContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
);

typedef VOID (NTAPI* POSK_KERNEL_ROUTINE)(
    _In_    PRKAPC               Apc,
    _Inout_ POSK_NORMAL_ROUTINE* NormalRoutine,
    _Inout_ PVOID*               NormalContext,
    _Inout_ PVOID*               SystemArgument1,
    _Inout_ PVOID*               SystemArgument2
);

typedef VOID (NTAPI* POSK_RUNDOWN_ROUTINE)(
    _In_ PRKAPC Apc
);

typedef enum _OSK_APC_ENVIRONMENT {
    OskOriginalApcEnvironment = 0,
    OskAttachedApcEnvironment = 1,
    OskCurrentApcEnvironment  = 2,
    OskInsertApcEnvironment   = 3
} OSK_APC_ENVIRONMENT;

extern "C" VOID NTAPI KeInitializeApc(
    _Out_    PRKAPC             Apc,
    _In_     PRKTHREAD          Thread,
    _In_     OSK_APC_ENVIRONMENT Environment,
    _In_     POSK_KERNEL_ROUTINE KernelRoutine,
    _In_opt_ POSK_RUNDOWN_ROUTINE RundownRoutine,
    _In_opt_ POSK_NORMAL_ROUTINE NormalRoutine,
    _In_opt_ KPROCESSOR_MODE    ApcMode,
    _In_opt_ PVOID              NormalContext
);

extern "C" BOOLEAN NTAPI KeInsertQueueApc(
    _Inout_ PRKAPC    Apc,
    _In_opt_ PVOID    SystemArgument1,
    _In_opt_ PVOID    SystemArgument2,
    _In_     KPRIORITY Increment
);

typedef PVOID (NTAPI* PFN_PS_GET_PROCESS_PEB)(
    _In_ PEPROCESS Process
);

static PFN_PS_GET_PROCESS_PEB ResolvePsGetProcessPeb()
{
    static PFN_PS_GET_PROCESS_PEB s_PsGetProcessPeb = nullptr;
    static BOOLEAN s_Resolved = FALSE;

    if (!s_Resolved) {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"PsGetProcessPeb");
        s_PsGetProcessPeb = (PFN_PS_GET_PROCESS_PEB)MmGetSystemRoutineAddress(&routineName);
        s_Resolved = TRUE;
    }

    return s_PsGetProcessPeb;
}

static PFN_PS_GET_NEXT_PROCESS_THREAD ResolvePsGetNextProcessThread()
{
    static PFN_PS_GET_NEXT_PROCESS_THREAD s_PsGetNextProcessThread = nullptr;
    static BOOLEAN s_Resolved = FALSE;

    if (!s_Resolved) {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"PsGetNextProcessThread");
        s_PsGetNextProcessThread =
            (PFN_PS_GET_NEXT_PROCESS_THREAD)MmGetSystemRoutineAddress(&routineName);
        s_Resolved = TRUE;
    }

    return s_PsGetNextProcessThread;
}

// APC 内核例程：APC 触发或被撤销时由内核调用，负责释放 APC 对象
static VOID ApcKernelRoutine(
    _In_    PRKAPC              Apc,
    _Inout_ POSK_NORMAL_ROUTINE* NormalRoutine,
    _Inout_ PVOID*              NormalContext,
    _Inout_ PVOID*              SystemArgument1,
    _Inout_ PVOID*              SystemArgument2)
{
    UNREFERENCED_PARAMETER(NormalRoutine);
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
    ExFreePoolWithTag(Apc, 'injA');
}

// 在已附加的地址空间内，从 PEB.Ldr 遍历模块找 LoadLibraryW
static PVOID FindLoadLibraryW_InAttached()
{
    PVOID result = nullptr;
    PFN_PS_GET_PROCESS_PEB getProcessPeb = ResolvePsGetProcessPeb();

    if (!getProcessPeb) {
        DbgPrint("[OpenSysKit] [Inject] PsGetProcessPeb unavailable\n");
        return nullptr;
    }

    __try {
        PVOID pPeb = getProcessPeb(PsGetCurrentProcess());
        if (!pPeb) __leave;

        ProbeForRead(pPeb, 0x20, 1);
        PVOID pLdr = *(PVOID*)((PUCHAR)pPeb + 0x18);
        if (!pLdr) __leave;

        PLIST_ENTRY head = (PLIST_ENTRY)((PUCHAR)pLdr + 0x10); // InLoadOrderModuleList
        ProbeForRead(head, sizeof(LIST_ENTRY), 1);
        PLIST_ENTRY cur = head->Flink;

        while (cur != head) {
            ProbeForRead(cur, 0x70, 1);

            PVOID          dllBase  = *(PVOID*)          ((PUCHAR)cur + 0x30);
            UNICODE_STRING* baseName = (UNICODE_STRING*)((PUCHAR)cur + 0x58);

            if (!dllBase || !baseName->Buffer || baseName->Length == 0) {
                cur = cur->Flink;
                continue;
            }

            ProbeForRead(baseName->Buffer, baseName->Length, 1);

            UNICODE_STRING kbName;
            RtlInitUnicodeString(&kbName, L"KERNELBASE.dll");
            if (!RtlEqualUnicodeString(baseName, &kbName, TRUE)) {
                cur = cur->Flink;
                continue;
            }

            // 找到 KERNELBASE.dll，解析 PE 导出表
            PUCHAR base = (PUCHAR)dllBase;
            ProbeForRead(base, 0x1000, 1);

            ULONG e_lfanew  = *(PULONG)(base + 0x3C);
            PUCHAR ntHdr    = base + e_lfanew;
            ProbeForRead(ntHdr, 0x100, 1);

            ULONG exportRva = *(PULONG)(ntHdr + 0x88); // DataDirectory[0].VirtualAddress
            if (!exportRva) { cur = cur->Flink; continue; }

            PUCHAR  expDir   = base + exportRva;
            ULONG   numNames = *(PULONG)(expDir + 0x18);
            PULONG  names    = (PULONG)(base + *(PULONG)(expDir + 0x20));
            PULONG  funcs    = (PULONG)(base + *(PULONG)(expDir + 0x1C));
            PUSHORT ords     = (PUSHORT)(base + *(PULONG)(expDir + 0x24));

            ProbeForRead(names, numNames * sizeof(ULONG), 1);
            ProbeForRead(ords,  numNames * sizeof(USHORT), 1);

            for (ULONG i = 0; i < numNames; i++) {
                PCHAR name = (PCHAR)(base + names[i]);
                ProbeForRead(name, 16, 1);
                if (strcmp(name, "LoadLibraryW") == 0) {
                    result = (PVOID)(base + funcs[ords[i]]);
                    __leave;
                }
            }
            break;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[OpenSysKit] [Inject] FindLoadLibraryW exception: 0x%08X\n",
            GetExceptionCode());
        result = nullptr;
    }

    return result;
}

NTSTATUS InjectDll(ULONG ProcessId, PCWSTR DllPath)
{
    if (!DllPath || DllPath[0] == L'\0') return STATUS_INVALID_PARAMETER;
    if (ProcessId == 0 || ProcessId == 4)  return STATUS_ACCESS_DENIED;

    SIZE_T pathLen = 0;
    while (DllPath[pathLen]) pathLen++;
    SIZE_T pathBytes = (pathLen + 1) * sizeof(WCHAR);
    if (pathBytes > 1040) return STATUS_INVALID_PARAMETER;

    PEPROCESS process = nullptr;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status)) return status;

    // 在目标进程地址空间内查找 LoadLibraryW 并分配路径缓冲区
    PVOID loadLibW  = nullptr;
    PVOID remoteBuf = nullptr;
    SIZE_T allocSize = pathBytes;

    KAPC_STATE apcState;
    KeStackAttachProcess(process, &apcState);

    loadLibW = FindLoadLibraryW_InAttached();

    if (loadLibW) {
        status = ZwAllocateVirtualMemory(
            ZwCurrentProcess(), &remoteBuf, 0,
            &allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (NT_SUCCESS(status)) {
            __try {
                ProbeForWrite(remoteBuf, pathBytes, 1);
                RtlCopyMemory(remoteBuf, DllPath, pathBytes);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                status = GetExceptionCode();
            }
        }
    } else {
        status = STATUS_NOT_FOUND;
    }

    KeUnstackDetachProcess(&apcState);

    if (!NT_SUCCESS(status)) {
        DbgPrint("[OpenSysKit] [Inject] prep failed: 0x%08X (PID=%lu)\n", status, ProcessId);
        ObDereferenceObject(process);
        return status;
    }

    DbgPrint("[OpenSysKit] [Inject] LoadLibraryW=%p remoteBuf=%p PID=%lu\n",
        loadLibW, remoteBuf, ProcessId);

    // 向目标进程的第一个非终止线程排队用户 APC
    BOOLEAN injected = FALSE;
    PFN_PS_GET_NEXT_PROCESS_THREAD getNextProcessThread = ResolvePsGetNextProcessThread();
    if (!getNextProcessThread) {
        ObDereferenceObject(process);
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    PETHREAD thread = getNextProcessThread(process, NULL);

    while (thread != NULL) {
        if (!PsIsThreadTerminating(thread)) {
            PRKAPC apc = (PRKAPC)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KAPC), 'injA');
            if (apc) {
                KeInitializeApc(
                    apc,
                    (PRKTHREAD)thread,
                    OskOriginalApcEnvironment,
                    ApcKernelRoutine,
                    nullptr,
                    (POSK_NORMAL_ROUTINE)loadLibW,  // 用户态 APC 例程 = LoadLibraryW
                    UserMode,
                    remoteBuf                    // 参数 = DLL 路径地址
                );

                if (KeInsertQueueApc(apc, nullptr, nullptr, IO_NO_INCREMENT)) {
                    DbgPrint("[OpenSysKit] [Inject] APC queued TID=%lu\n",
                        (ULONG)(ULONG_PTR)PsGetThreadId(thread));
                    injected = TRUE;
                    PETHREAD next = getNextProcessThread(process, thread);
                    ObDereferenceObject(thread);
                    thread = next;
                    break;
                } else {
                    ExFreePoolWithTag(apc, 'injA');
                }
            }
        }

        PETHREAD next = getNextProcessThread(process, thread);
        ObDereferenceObject(thread);
        thread = next;
    }

    while (thread) {
        PETHREAD next = getNextProcessThread(process, thread);
        ObDereferenceObject(thread);
        thread = next;
    }

    ObDereferenceObject(process);
    return injected ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}
