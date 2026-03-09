#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x0A000008
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include <ntifs.h>
#include "token.h"


// ========== EX_FAST_REF ==========
#define EX_FAST_REF_MASK        ((ULONG_PTR)0xF)
#define EX_FAST_REF_REFCNT_MAX  ((ULONG_PTR)0xF)
#define EXFASTREF_TO_PTR(r)     ((PVOID)((ULONG_PTR)(r) & ~EX_FAST_REF_MASK))

// ========== 系统进程信息结构 ==========

typedef struct _SYSTEM_PROCESS_INFO {
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
} SYSTEM_PROCESS_INFO, *PSYSTEM_PROCESS_INFO;

extern "C" NTSTATUS NTAPI ZwQuerySystemInformation(
    ULONG  SystemInformationClass,
    PVOID  SystemInformation,
    ULONG  SystemInformationLength,
    PULONG ReturnLength
);

// ZwCreateToken — 内核构造任意 Token
extern "C" NTSTATUS NTAPI ZwCreateToken(
    _Out_    PHANDLE             TokenHandle,
    _In_     ACCESS_MASK         DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES  ObjectAttributes,
    _In_     TOKEN_TYPE          TokenType,
    _In_     PLUID               AuthenticationId,
    _In_     PLARGE_INTEGER      ExpirationTime,
    _In_     PTOKEN_USER         TokenUser,
    _In_     PTOKEN_GROUPS       TokenGroups,
    _In_     PTOKEN_PRIVILEGES   TokenPrivileges,
    _In_opt_ PTOKEN_OWNER        TokenOwner,
    _In_     PTOKEN_PRIMARY_GROUP TokenPrimaryGroup,
    _In_opt_ PTOKEN_DEFAULT_DACL TokenDefaultDacl,
    _In_     PTOKEN_SOURCE       TokenSource
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
        // 48 8B 81 xx xx 00 00 => MOV RAX,[RCX+imm32]
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

// ========== EX_FAST_REF 安全替换 ==========
//
// 正确流程：
//   1. 读取 source 的 EX_FAST_REF，掩掉低4位得到真实 Token 指针
//   2. ObReferenceObjectByPointer 增加引用（防止对象提前释放）
//   3. 构造新 EX_FAST_REF = ptr | 0xF（低位填满，与系统行为一致）
//   4. InterlockedExchangePointer 原子写入 target，拿回旧值
//   5. 旧 Token 指针掩低位后 ObDereferenceObject 释放引用
//
static NTSTATUS SwapProcessToken(
    _In_ PEPROCESS targetProcess,
    _In_ PEPROCESS sourceProcess)
{
    // 1. 读取 source Token 的原始 EX_FAST_REF 值
    ULONG_PTR srcRaw = *(volatile ULONG_PTR*)((PUCHAR)sourceProcess + g_TokenOffset);
    PACCESS_TOKEN srcToken = (PACCESS_TOKEN)EXFASTREF_TO_PTR(srcRaw);
    if (!srcToken) {
        DbgPrint("[OpenSysKit] [Token] SwapProcessToken: source token ptr is NULL\n");
        return STATUS_UNSUCCESSFUL;
    }

    // 2. 增加 srcToken 引用计数
    NTSTATUS status = ObReferenceObjectByPointer(
        srcToken,
        TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY,
        *SeTokenObjectType,
        KernelMode);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[OpenSysKit] [Token] ObReferenceObjectByPointer failed: 0x%08X\n", status);
        return status;
    }

    // 3. 构造新的 EX_FAST_REF（低4位填满）
    ULONG_PTR newRef = (ULONG_PTR)srcToken | EX_FAST_REF_REFCNT_MAX;

    // 4. 原子替换，取回旧的 EX_FAST_REF
    ULONG_PTR oldRef = (ULONG_PTR)InterlockedExchangePointer(
        (PVOID*)((PUCHAR)targetProcess + g_TokenOffset),
        (PVOID)newRef);

    // 5. 释放旧 Token 引用
    PACCESS_TOKEN oldToken = (PACCESS_TOKEN)EXFASTREF_TO_PTR(oldRef);
    if (oldToken) {
        ObDereferenceObject(oldToken);
    }

    DbgPrint("[OpenSysKit] [Token] SwapProcessToken: 0x%llX -> 0x%llX\n",
        (ULONG64)oldRef, (ULONG64)newRef);
    return STATUS_SUCCESS;
}

// ========== 按进程名查找 EPROCESS ==========

static NTSTATUS FindProcessByNameInternal(
    _In_     PCWSTR    targetName,
    _In_opt_ PULONG    SessionId,
    _Out_    PEPROCESS* outProcess)
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
            if (RtlEqualUnicodeString(&entry->ImageName, &target, TRUE) &&
                (SessionId == nullptr || entry->SessionId == *SessionId)) {
                PEPROCESS proc = nullptr;
                if (NT_SUCCESS(PsLookupProcessByProcessId(entry->UniqueProcessId, &proc))) {
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

static NTSTATUS GetProcessSessionId(_In_ ULONG ProcessId, _Out_ PULONG SessionId)
{
    *SessionId = 0;

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

    status = STATUS_NOT_FOUND;
    PSYSTEM_PROCESS_INFO entry = (PSYSTEM_PROCESS_INFO)buf;
    while (TRUE) {
        if ((ULONG_PTR)entry->UniqueProcessId == (ULONG_PTR)ProcessId) {
            *SessionId = entry->SessionId;
            status = STATUS_SUCCESS;
            break;
        }
        if (entry->NextEntryOffset == 0) break;
        entry = (PSYSTEM_PROCESS_INFO)((PUCHAR)entry + entry->NextEntryOffset);
    }

    ExFreePoolWithTag(buf, 'koTk');
    return status;
}

// ========== Level 1: SYSTEM ==========

static NTSTATUS ElevateToSystem(_In_ PEPROCESS targetProcess)
{
    PEPROCESS systemProc = nullptr;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)4, &systemProc);
    if (!NT_SUCCESS(status)) return status;

    status = SwapProcessToken(targetProcess, systemProc);
    ObDereferenceObject(systemProc);
    return status;
}

// ========== Level 0: Admin ==========

static NTSTATUS ElevateToAdmin(_In_ PEPROCESS targetProcess)
{
    PEPROCESS proc = nullptr;
    NTSTATUS status = FindProcessByNameInternal(L"winlogon.exe", nullptr, &proc);
    if (!NT_SUCCESS(status))
        status = FindProcessByNameInternal(L"lsass.exe", nullptr, &proc);

    if (!NT_SUCCESS(status)) {
        DbgPrint("[OpenSysKit] [Token] Admin: neither winlogon nor lsass found\n");
        return status;
    }

    status = SwapProcessToken(targetProcess, proc);
    ObDereferenceObject(proc);
    return status;
}

// ========== Level 3: StandardUser ==========

static NTSTATUS ElevateToStandardUser(
    _In_ ULONG     TargetProcessId,
    _In_ PEPROCESS targetProcess)
{
    static const PCWSTR kCandidates[] = {
        L"explorer.exe",
        L"ShellExperienceHost.exe",
        L"StartMenuExperienceHost.exe",
        L"SearchHost.exe",
        L"RuntimeBroker.exe",
    };

    ULONG sessionId = 0;
    NTSTATUS status = GetProcessSessionId(TargetProcessId, &sessionId);
    if (!NT_SUCCESS(status)) return status;

    for (ULONG i = 0; i < RTL_NUMBER_OF(kCandidates); ++i) {
        PEPROCESS proc = nullptr;
        status = FindProcessByNameInternal(kCandidates[i], &sessionId, &proc);
        if (!NT_SUCCESS(status)) continue;

        DbgPrint("[OpenSysKit] [Token] StandardUser: source=%ws session=%lu\n",
            kCandidates[i], sessionId);
        status = SwapProcessToken(targetProcess, proc);
        ObDereferenceObject(proc);
        return status;
    }

    DbgPrint("[OpenSysKit] [Token] StandardUser: no shell found in session=%lu\n", sessionId);
    return STATUS_NOT_FOUND;
}

// ========== Level 2: TrustedInstaller — ZwCreateToken 构造 ==========
//
// 构造一个完整的 TrustedInstaller Token，包含：
//
//   User    : NT SERVICE\TrustedInstaller
//             S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464
//
//   Groups  :
//     S-1-5-18   NT AUTHORITY\SYSTEM                (SE_GROUP_ENABLED|MANDATORY|OWNER)
//     S-1-5-32-544 BUILTIN\Administrators           (SE_GROUP_ENABLED|MANDATORY|OWNER)
//     S-1-5-11   Authenticated Users                (SE_GROUP_ENABLED|MANDATORY)
//     S-1-1-0    Everyone                           (SE_GROUP_ENABLED|MANDATORY)
//     S-1-16-16384 Mandatory Label\System Level     (Integrity)
//
//   Privileges: 全部35个特权，全部启用（SE_PRIVILEGE_ENABLED|SE_PRIVILEGE_ENABLED_BY_DEFAULT）
//
//   Primary Group : BUILTIN\Administrators (S-1-5-32-544)
//   Owner         : BUILTIN\Administrators (S-1-5-32-544)
//

// SID 辅助宏
#define SID_SIZE(subCount) (sizeof(SID) - sizeof(ULONG) + (subCount) * sizeof(ULONG))

#pragma pack(push, 1)
// 静态 SID 结构体（最多6个SubAuthority）
typedef struct _SID_MAX6 {
    BYTE  Revision;
    BYTE  SubAuthorityCount;
    SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
    ULONG SubAuthority[6];
} SID_MAX6;
#pragma pack(pop)

static VOID InitSid(SID_MAX6* s, BYTE subCount,
    BYTE ia0, BYTE ia1, BYTE ia2, BYTE ia3, BYTE ia4, BYTE ia5,
    ...)
{
    s->Revision = SID_REVISION;
    s->SubAuthorityCount = subCount;
    s->IdentifierAuthority.Value[0] = ia0;
    s->IdentifierAuthority.Value[1] = ia1;
    s->IdentifierAuthority.Value[2] = ia2;
    s->IdentifierAuthority.Value[3] = ia3;
    s->IdentifierAuthority.Value[4] = ia4;
    s->IdentifierAuthority.Value[5] = ia5;
    va_list args;
    va_start(args, ia5);
    for (BYTE i = 0; i < subCount; i++)
        s->SubAuthority[i] = va_arg(args, ULONG);
    va_end(args);
}

// 全部特权 LUID（1~35）
static const ULONG kAllPrivileges[] = {
     2,  3,  4,  5,  6,  7,  8,  9, 10, 11,
    12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
    22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    32, 33, 34, 35, 36
};
#define ALL_PRIV_COUNT RTL_NUMBER_OF(kAllPrivileges)

static NTSTATUS BuildTrustedInstallerToken(_Out_ HANDLE* outToken)
{
    *outToken = NULL;
    NTSTATUS status;

    // ----- SID 定义 -----

    // NT SERVICE\TrustedInstaller
    // S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464
    SID_MAX6 sidTI;
    InitSid(&sidTI, 6, 0,0,0,0,0,5,
        80u, 956008885u, 3418522649u, 1831038044u, 1853292631u, 2271478464u);

    // NT AUTHORITY\SYSTEM  S-1-5-18
    SID_MAX6 sidSystem;
    InitSid(&sidSystem, 1, 0,0,0,0,0,5, 18u, 0,0,0,0,0);

    // BUILTIN\Administrators  S-1-5-32-544
    SID_MAX6 sidAdmins;
    InitSid(&sidAdmins, 2, 0,0,0,0,0,5, 32u, 544u, 0,0,0,0);

    // Authenticated Users  S-1-5-11
    SID_MAX6 sidAuth;
    InitSid(&sidAuth, 1, 0,0,0,0,0,5, 11u, 0,0,0,0,0);

    // Everyone  S-1-1-0
    SID_MAX6 sidEveryone;
    InitSid(&sidEveryone, 1, 0,0,0,0,0,1, 0u, 0,0,0,0,0);

    // Mandatory Label\System Level  S-1-16-16384
    SID_MAX6 sidIntegrity;
    InitSid(&sidIntegrity, 1, 0,0,0,0,0,16, 16384u, 0,0,0,0,0);

    // ----- TOKEN_USER -----
    TOKEN_USER tokenUser;
    tokenUser.User.Sid        = (PSID)&sidTI;
    tokenUser.User.Attributes = 0;

    // ----- TOKEN_GROUPS（5 个组 + 1 个完整性标签）-----
    //   ZwCreateToken 的 Groups 里可以包含 Integrity Label 组，
    //   也可以通过 ZwSetInformationToken 单独设置，这里一并放入。
    enum { GROUP_COUNT = 6 };

    struct {
        ULONG           GroupCount;
        SID_AND_ATTRIBUTES Groups[GROUP_COUNT];
    } tokenGroups;

    tokenGroups.GroupCount = GROUP_COUNT;

    tokenGroups.Groups[0].Sid        = (PSID)&sidSystem;
    tokenGroups.Groups[0].Attributes = SE_GROUP_ENABLED | SE_GROUP_MANDATORY |
                                       SE_GROUP_OWNER;

    tokenGroups.Groups[1].Sid        = (PSID)&sidAdmins;
    tokenGroups.Groups[1].Attributes = SE_GROUP_ENABLED | SE_GROUP_MANDATORY |
                                       SE_GROUP_OWNER;

    tokenGroups.Groups[2].Sid        = (PSID)&sidAuth;
    tokenGroups.Groups[2].Attributes = SE_GROUP_ENABLED | SE_GROUP_MANDATORY;

    tokenGroups.Groups[3].Sid        = (PSID)&sidEveryone;
    tokenGroups.Groups[3].Attributes = SE_GROUP_ENABLED | SE_GROUP_MANDATORY;

    // Local (S-1-2-0)
    SID_MAX6 sidLocal;
    InitSid(&sidLocal, 1, 0,0,0,0,0,2, 0u, 0,0,0,0,0);
    tokenGroups.Groups[4].Sid        = (PSID)&sidLocal;
    tokenGroups.Groups[4].Attributes = SE_GROUP_ENABLED | SE_GROUP_MANDATORY;

    // Integrity label — 放最后
    tokenGroups.Groups[5].Sid        = (PSID)&sidIntegrity;
    tokenGroups.Groups[5].Attributes = SE_GROUP_INTEGRITY | SE_GROUP_INTEGRITY_ENABLED;

    // ----- TOKEN_PRIVILEGES（全部特权，均启用）-----
    ULONG privBufSize = sizeof(ULONG) + ALL_PRIV_COUNT * sizeof(LUID_AND_ATTRIBUTES);
    PTOKEN_PRIVILEGES tokenPrivs = (PTOKEN_PRIVILEGES)
        ExAllocatePool2(POOL_FLAG_NON_PAGED, privBufSize, 'koTk');
    if (!tokenPrivs) return STATUS_INSUFFICIENT_RESOURCES;

    tokenPrivs->PrivilegeCount = ALL_PRIV_COUNT;
    for (ULONG i = 0; i < ALL_PRIV_COUNT; i++) {
        tokenPrivs->Privileges[i].Luid.LowPart  = kAllPrivileges[i];
        tokenPrivs->Privileges[i].Luid.HighPart = 0;
        tokenPrivs->Privileges[i].Attributes    =
            SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT;
    }

    // ----- Owner / PrimaryGroup -----
    TOKEN_OWNER tokenOwner;
    tokenOwner.Owner = (PSID)&sidAdmins;

    TOKEN_PRIMARY_GROUP tokenPrimaryGroup;
    tokenPrimaryGroup.PrimaryGroup = (PSID)&sidAdmins;

    // ----- DefaultDacl（NULL = 允许所有访问）-----
    TOKEN_DEFAULT_DACL tokenDacl;
    tokenDacl.DefaultDacl = nullptr;

    // ----- SOURCE -----
    TOKEN_SOURCE tokenSource;
    RtlCopyMemory(tokenSource.SourceName, "TIBuild\0", 8); // 8字节
    ExAllocateLocallyUniqueId(&tokenSource.SourceIdentifier);

    // ----- AuthenticationId — 使用 SYSTEM_LUID -----
    LUID authId = SYSTEM_LUID;  // {999, 0}

    // ----- ExpirationTime（不过期）-----
    LARGE_INTEGER expiry;
    expiry.QuadPart = 0x7FFFFFFFFFFFFFFF;

    // ----- ObjectAttributes -----
    OBJECT_ATTRIBUTES objAttr;
    SECURITY_QUALITY_OF_SERVICE sqos = {
        sizeof(SECURITY_QUALITY_OF_SERVICE),
        SecurityImpersonation,
        SECURITY_STATIC_TRACKING,
        FALSE
    };
    InitializeObjectAttributes(&objAttr, nullptr, 0, nullptr, nullptr);
    objAttr.SecurityQualityOfService = &sqos;

    // ----- ZwCreateToken -----
    HANDLE hToken = NULL;
    status = ZwCreateToken(
        &hToken,
        TOKEN_ALL_ACCESS,
        &objAttr,
        TokenPrimary,
        &authId,
        &expiry,
        &tokenUser,
        (PTOKEN_GROUPS)&tokenGroups,
        tokenPrivs,
        &tokenOwner,
        &tokenPrimaryGroup,
        &tokenDacl,
        &tokenSource
    );

    ExFreePoolWithTag(tokenPrivs, 'koTk');

    if (!NT_SUCCESS(status)) {
        DbgPrint("[OpenSysKit] [Token] ZwCreateToken failed: 0x%08X\n", status);
        return status;
    }

    *outToken = hToken;
    DbgPrint("[OpenSysKit] [Token] ZwCreateToken succeeded, handle=0x%p\n", hToken);
    return STATUS_SUCCESS;
}

// 将 ZwCreateToken 产生的 Handle 转为 Token 对象，然后用 SwapProcessToken 的逻辑写入
static NTSTATUS ElevateToTrustedInstaller(_In_ PEPROCESS targetProcess)
{
    // 1. 先尝试找正在运行的 TrustedInstaller.exe（最准确）
    PEPROCESS tiProc = nullptr;
    NTSTATUS status = FindProcessByNameInternal(L"TrustedInstaller.exe", nullptr, &tiProc);
    if (NT_SUCCESS(status)) {
        DbgPrint("[OpenSysKit] [Token] TI: found running process, copying token\n");
        status = SwapProcessToken(targetProcess, tiProc);
        ObDereferenceObject(tiProc);
        return status;
    }

    DbgPrint("[OpenSysKit] [Token] TI: process not running, constructing token via ZwCreateToken\n");

    // 2. 进程不存在则构造
    HANDLE hToken = NULL;
    status = BuildTrustedInstallerToken(&hToken);
    if (!NT_SUCCESS(status)) return status;

    // 3. Handle -> 内核对象指针
    PACCESS_TOKEN tokenObj = nullptr;
    status = ObReferenceObjectByHandle(
        hToken,
        TOKEN_ALL_ACCESS,
        *SeTokenObjectType,
        KernelMode,
        (PVOID*)&tokenObj,
        nullptr);

    ZwClose(hToken);

    if (!NT_SUCCESS(status)) {
        DbgPrint("[OpenSysKit] [Token] ObReferenceObjectByHandle failed: 0x%08X\n", status);
        return status;
    }

    // 4. 写入目标进程（复用 SwapProcessToken 的引用计数逻辑）
    //    此时 tokenObj 已经 Reference 过一次（来自 ObReferenceObjectByHandle）
    //    再额外 Reference 一次供 EX_FAST_REF 使用，与 SwapProcessToken 内部行为一致
    NTSTATUS refStatus = ObReferenceObjectByPointer(
        tokenObj,
        TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY,
        *SeTokenObjectType,
        KernelMode);

    if (!NT_SUCCESS(refStatus)) {
        ObDereferenceObject(tokenObj);
        return refStatus;
    }

    ULONG_PTR newRef = (ULONG_PTR)tokenObj | EX_FAST_REF_REFCNT_MAX;
    ULONG_PTR oldRef = (ULONG_PTR)InterlockedExchangePointer(
        (PVOID*)((PUCHAR)targetProcess + g_TokenOffset),
        (PVOID)newRef);

    PACCESS_TOKEN oldToken = (PACCESS_TOKEN)EXFASTREF_TO_PTR(oldRef);
    if (oldToken) ObDereferenceObject(oldToken);

    // 释放 ObReferenceObjectByHandle 那次引用
    ObDereferenceObject(tokenObj);

    DbgPrint("[OpenSysKit] [Token] TI: token installed via ZwCreateToken\n");
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

    PEPROCESS targetProcess = nullptr;
    NTSTATUS status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)ProcessId, &targetProcess);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[OpenSysKit] [Token] lookup PID=%lu failed: 0x%08X\n", ProcessId, status);
        return status;
    }

    switch (Level) {
    case ELEVATE_LEVEL_ADMIN:
        DbgPrint("[OpenSysKit] [Token] PID=%lu -> Admin\n", ProcessId);
        status = ElevateToAdmin(targetProcess);
        break;

    case ELEVATE_LEVEL_SYSTEM:
        DbgPrint("[OpenSysKit] [Token] PID=%lu -> SYSTEM\n", ProcessId);
        status = ElevateToSystem(targetProcess);
        break;

    case ELEVATE_LEVEL_TRUSTED_INSTALLER:
        DbgPrint("[OpenSysKit] [Token] PID=%lu -> TrustedInstaller\n", ProcessId);
        status = ElevateToTrustedInstaller(targetProcess);
        break;

    case ELEVATE_LEVEL_STANDARD_USER:
        DbgPrint("[OpenSysKit] [Token] PID=%lu -> StandardUser\n", ProcessId);
        status = ElevateToStandardUser(ProcessId, targetProcess);
        break;

    default:
        DbgPrint("[OpenSysKit] [Token] unknown Level=%lu\n", Level);
        status = STATUS_INVALID_PARAMETER;
        break;
    }

    ObDereferenceObject(targetProcess);

    if (NT_SUCCESS(status)) {
        DbgPrint("[OpenSysKit] [Token] PID=%lu elevation done (Level=%lu)\n", ProcessId, Level);
    } else {
        DbgPrint("[OpenSysKit] [Token] PID=%lu elevation failed (Level=%lu): 0x%08X\n",
            ProcessId, Level, status);
    }

    return status;
}
