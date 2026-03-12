#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x0A000008
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include <ntifs.h>
#include <ntstrsafe.h>
#include "network.h"

// ========== 网络连接枚举 ==========
//
// 通过 ZwQuerySystemInformation(SystemExtendedHandleInformation) 的方案
// 无法直接关联端口到 PID，最可靠的内核方案是：
//
//   ZwDeviceIoControlFile -> \Device\Tcp (或 \Device\Udp)
//   使用 IOCTL_TCP_QUERY_INFORMATION_EX（TDI 接口，兼容 Win10）
//
// 不过 TDI 在 Win8+ 标记为 deprecated，更稳妥的方案是：
//   ZwQuerySystemInformation(SystemExtendedProcessInformation) 不含网络信息；
//   通过 Nsi（Network Store Interface）驱动的 IOCTL 查询。
//
// Nsi 方案：
//   打开 \Device\Nsi，发送 IOCTL_NSI_PROXY_IOCTL_COUNT + IOCTL_NSI_PROXY_IOCTL_ENUMERATE_TABLE
//   获取 TCP/UDP 连接表（包含本地/远端地址+端口+PID+状态）。
//   这是 netstat/TCPView 在用户态的底层实现。
//
// 此处实现 Nsi 枚举方案（IPv4 TCP + UDP，IPv6 结构相同，偏移不同）。
//

// Nsi IOCTL 控制码
#define IOCTL_NSI_PROXY_IOCTL_BASE              0x12
#define NSI_PROXY_IOCTL_ENUMERATE_TABLE_STEADY  \
    CTL_CODE(IOCTL_NSI_PROXY_IOCTL_BASE, 3, METHOD_BUFFERED, FILE_ANY_ACCESS)

// 模块 ID（TCP/UDP IPv4/IPv6）
// 这些 GUID 是 Nsi 内部模块标识，Win7~Win11 保持一致
static const GUID NPI_MS_TCP_MODULEID  =
    { 0xEB004A03, 0x9B1A, 0x11D4, {0x91,0x23,0x00,0x50,0x04,0x77,0x59,0xBC} };
static const GUID NPI_MS_UDP_MODULEID  =
    { 0xEB004A01, 0x9B1A, 0x11D4, {0x91,0x23,0x00,0x50,0x04,0x77,0x59,0xBC} };

// NSI 枚举请求头
typedef struct _NSI_ENUMERATE_TABLE_REQUEST {
    ULONG       RsvdMustBeZero;
    ULONG       Flags;
    GUID        ModuleId;
    ULONG       NsiType;         // 1 = static table, 2 = connection table
    ULONG       EntrySize;
    ULONG       AllocCount;      // entries 缓冲区容量
    ULONG       Count;           // 返回的条目数（输出）
    PVOID       KeyBuf;          // 键缓冲区（地址+端口+PID）
    ULONG       KeyEntrySize;
    PVOID       RodBuf;          // 只读数据（状态）
    ULONG       RodEntrySize;
    PVOID       DynBuf;
    ULONG       DynEntrySize;
} NSI_ENUMERATE_TABLE_REQUEST;

// IPv4 TCP 连接条目键（24字节）
typedef struct _NSI_TCP4_ENTRY {
    ULONG   LocalAddr;
    ULONG   Pad0;
    USHORT  LocalPort;
    UCHAR   Pad1[2];
    ULONG   RemoteAddr;
    ULONG   Pad2;
    USHORT  RemotePort;
    UCHAR   Pad3[2];
} NSI_TCP4_ENTRY;

// IPv4 UDP 连接条目键（16字节）
typedef struct _NSI_UDP4_ENTRY {
    ULONG   LocalAddr;
    ULONG   Pad0;
    USHORT  LocalPort;
    UCHAR   Pad1[2];
} NSI_UDP4_ENTRY;

// 连接状态（TCP ROD）
typedef struct _NSI_TCP_ROD {
    ULONG   State;
    ULONG   OwningPid;
    // 还有更多字段，只取前两个
} NSI_TCP_ROD;

typedef struct _NSI_UDP_ROD {
    ULONG   Pad[4];
    ULONG   OwningPid;
} NSI_UDP_ROD;

#define NSI_MAX_ENTRIES 4096

static NTSTATUS QueryNsiTable(
    _In_    HANDLE  hNsi,
    _In_    BOOLEAN isTcp,
    _Out_   PVOID   OutputBuffer,
    _In_    ULONG   OutputBufferSize,
    _Inout_ PULONG  outCount,
    _In_    ULONG   maxOut)
{
    ULONG entryCount = NSI_MAX_ENTRIES;
    ULONG keySize    = isTcp ? sizeof(NSI_TCP4_ENTRY) : sizeof(NSI_UDP4_ENTRY);
    ULONG rodSize    = isTcp ? sizeof(NSI_TCP_ROD)    : sizeof(NSI_UDP_ROD);

    PVOID keyBuf = ExAllocatePool2(POOL_FLAG_NON_PAGED, entryCount * keySize, 'nsiK');
    PVOID rodBuf = ExAllocatePool2(POOL_FLAG_NON_PAGED, entryCount * rodSize, 'nsiR');
    if (!keyBuf || !rodBuf) {
        if (keyBuf) ExFreePoolWithTag(keyBuf, 'nsiK');
        if (rodBuf) ExFreePoolWithTag(rodBuf, 'nsiR');
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    NSI_ENUMERATE_TABLE_REQUEST req = { 0 };
    req.ModuleId      = isTcp ? NPI_MS_TCP_MODULEID : NPI_MS_UDP_MODULEID;
    req.NsiType       = 2;
    req.AllocCount    = entryCount;
    req.KeyBuf        = keyBuf;
    req.KeyEntrySize  = keySize;
    req.RodBuf        = rodBuf;
    req.RodEntrySize  = rodSize;

    IO_STATUS_BLOCK iosb = { 0 };
    NTSTATUS status = ZwDeviceIoControlFile(
        hNsi, NULL, NULL, NULL, &iosb,
        NSI_PROXY_IOCTL_ENUMERATE_TABLE_STEADY,
        &req, sizeof(req), &req, sizeof(req));

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(keyBuf, 'nsiK');
        ExFreePoolWithTag(rodBuf, 'nsiR');
        return status;
    }

    PCONNECTION_INFO connOut = (PCONNECTION_INFO)
        ((PUCHAR)OutputBuffer + sizeof(CONNECTION_LIST_HEADER) + *outCount * sizeof(CONNECTION_INFO));
    ULONG filled = req.Count;

    for (ULONG i = 0; i < filled && *outCount < maxOut; i++) {
        if (isTcp) {
            NSI_TCP4_ENTRY* k = (NSI_TCP4_ENTRY*)keyBuf + i;
            NSI_TCP_ROD*    r = (NSI_TCP_ROD*)rodBuf + i;

            connOut->Protocol  = CONNECTION_PROTO_TCP;
            connOut->State     = r->State;
            connOut->ProcessId = r->OwningPid;
            connOut->IsIPv6    = FALSE;
            RtlCopyMemory(connOut->LocalAddr,  &k->LocalAddr,  4);
            RtlCopyMemory(connOut->RemoteAddr, &k->RemoteAddr, 4);
            connOut->LocalPort  = RtlUshortByteSwap(k->LocalPort);
            connOut->RemotePort = RtlUshortByteSwap(k->RemotePort);
        } else {
            NSI_UDP4_ENTRY* k = (NSI_UDP4_ENTRY*)keyBuf + i;
            NSI_UDP_ROD*    r = (NSI_UDP_ROD*)rodBuf + i;

            connOut->Protocol  = CONNECTION_PROTO_UDP;
            connOut->State     = 0;
            connOut->ProcessId = r->OwningPid;
            connOut->IsIPv6    = FALSE;
            RtlCopyMemory(connOut->LocalAddr, &k->LocalAddr, 4);
            RtlZeroMemory(connOut->RemoteAddr, 16);
            connOut->LocalPort  = RtlUshortByteSwap(k->LocalPort);
            connOut->RemotePort = 0;
        }

        connOut++;
        (*outCount)++;
    }

    ExFreePoolWithTag(keyBuf, 'nsiK');
    ExFreePoolWithTag(rodBuf, 'nsiR');
    return STATUS_SUCCESS;
}

NTSTATUS EnumConnections(
    _Out_ PVOID  OutputBuffer,
    _In_  ULONG  OutputBufferSize,
    _Out_ PULONG BytesWritten)
{
    *BytesWritten = 0;

    if (OutputBufferSize < sizeof(CONNECTION_LIST_HEADER))
        return STATUS_BUFFER_TOO_SMALL;

    // NSI 内核接口在 Win11 上返回 STATUS_NOT_IMPLEMENTED，暂时禁用
    PCONNECTION_LIST_HEADER header = (PCONNECTION_LIST_HEADER)OutputBuffer;
    header->Count     = 0;
    header->TotalSize = sizeof(CONNECTION_LIST_HEADER);
    *BytesWritten     = sizeof(CONNECTION_LIST_HEADER);
    return STATUS_SUCCESS;
}
