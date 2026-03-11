//
// PE Signature Verification for OpenSysKit Driver
// Ported from WinDrive/DriverLoader
// Uses certificate SHA1 thumbprint for verification
//

#include <ntddk.h>
#include <ntimage.h>
#include "signature.h"

#ifdef DBG
#define SigLog(fmt, ...) DbgPrint("[OpenSysKit][Sig] " fmt "\n", ##__VA_ARGS__)
#else
#define SigLog(fmt, ...)
#endif

extern "C" {
    NTSTATUS NTAPI ZwQueryInformationProcess(
        HANDLE ProcessHandle,
        ULONG ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength
    );

    NTSTATUS NTAPI ObOpenObjectByPointer(
        PVOID Object,
        ULONG HandleAttributes,
        PACCESS_STATE PassedAccessState,
        ACCESS_MASK DesiredAccess,
        POBJECT_TYPE ObjectType,
        KPROCESSOR_MODE AccessMode,
        PHANDLE Handle
    );

    extern POBJECT_TYPE *PsProcessType;
}

#define ProcessImageFileName 27

static PVOID SigAllocMem(SIZE_T Size)
{
#ifdef POOL_FLAG_NON_PAGED
    return ExAllocatePool2(POOL_FLAG_NON_PAGED, Size, SIGNATURE_TAG);
#else
    #pragma warning(suppress: 4996)
    PVOID p = ExAllocatePoolWithTag(NonPagedPool, Size, SIGNATURE_TAG);
    if (p) RtlZeroMemory(p, Size);
    return p;
#endif
}

static VOID SigFreeMem(PVOID Ptr)
{
    if (Ptr) ExFreePoolWithTag(Ptr, SIGNATURE_TAG);
}

// ================================================================
// SHA256 implementation
// ================================================================

struct SHA256_CTX {
    ULONG state[8];
    ULONG64 count;
    UCHAR buffer[64];
};

struct SHA1_CTX {
    ULONG state[5];
    ULONG count[2];
    UCHAR buffer[64];
};

#define ROL(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))
#define ROR(value, bits) (((value) >> (bits)) | ((value) << (32 - (bits))))

static const ULONG K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void SHA256Transform(ULONG state[8], const UCHAR buffer[64])
{
    ULONG a, b, c, d, e, f, g, h, t1, t2;
    ULONG W[64];

    for (ULONG i = 0; i < 16; i++) {
        W[i] = ((ULONG)buffer[i * 4] << 24) |
               ((ULONG)buffer[i * 4 + 1] << 16) |
               ((ULONG)buffer[i * 4 + 2] << 8) |
               ((ULONG)buffer[i * 4 + 3]);
    }
    for (ULONG i = 16; i < 64; i++) {
        ULONG s0 = ROR(W[i-15], 7) ^ ROR(W[i-15], 18) ^ (W[i-15] >> 3);
        ULONG s1 = ROR(W[i-2], 17) ^ ROR(W[i-2], 19) ^ (W[i-2] >> 10);
        W[i] = W[i-16] + s0 + W[i-7] + s1;
    }

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    for (ULONG i = 0; i < 64; i++) {
        ULONG S1 = ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25);
        ULONG ch = (e & f) ^ ((~e) & g);
        t1 = h + S1 + ch + K256[i] + W[i];
        ULONG S0 = ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22);
        ULONG maj = (a & b) ^ (a & c) ^ (b & c);
        t2 = S0 + maj;

        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

static void SHA256Init(SHA256_CTX* ctx)
{
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
}

static void SHA256Update(SHA256_CTX* ctx, const UCHAR* data, ULONG len)
{
    ULONG bufferIndex = (ULONG)(ctx->count & 63);
    ctx->count += len;

    if (bufferIndex + len >= 64) {
        ULONG firstPart = 64 - bufferIndex;
        RtlCopyMemory(&ctx->buffer[bufferIndex], data, firstPart);
        SHA256Transform(ctx->state, ctx->buffer);

        ULONG i;
        for (i = firstPart; i + 63 < len; i += 64) {
            SHA256Transform(ctx->state, &data[i]);
        }
        bufferIndex = 0;
        data += i;
        len -= i;
    }
    RtlCopyMemory(&ctx->buffer[bufferIndex], data, len);
}

static void SHA256Final(UCHAR digest[32], SHA256_CTX* ctx)
{
    UCHAR finalcount[8];
    ULONG64 bitCount = ctx->count * 8;

    for (ULONG i = 0; i < 8; i++) {
        finalcount[i] = (UCHAR)((bitCount >> ((7 - i) * 8)) & 0xFF);
    }

    UCHAR c = 0x80;
    SHA256Update(ctx, &c, 1);
    while ((ctx->count & 63) != 56) {
        c = 0;
        SHA256Update(ctx, &c, 1);
    }
    SHA256Update(ctx, finalcount, 8);

    for (ULONG i = 0; i < 32; i++) {
        digest[i] = (UCHAR)((ctx->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 0xFF);
    }
}

// ================================================================
// SHA1 implementation
// ================================================================

static void SHA1Transform(ULONG state[5], const UCHAR buffer[64])
{
    ULONG a, b, c, d, e;
    ULONG block[80];

    for (ULONG i = 0; i < 16; i++) {
        block[i] = ((ULONG)buffer[i * 4] << 24) |
                   ((ULONG)buffer[i * 4 + 1] << 16) |
                   ((ULONG)buffer[i * 4 + 2] << 8) |
                   ((ULONG)buffer[i * 4 + 3]);
    }
    for (ULONG i = 16; i < 80; i++) {
        block[i] = ROL(block[i-3] ^ block[i-8] ^ block[i-14] ^ block[i-16], 1);
    }

    a = state[0]; b = state[1]; c = state[2]; d = state[3]; e = state[4];

    for (ULONG i = 0; i < 20; i++) {
        ULONG temp = ROL(a, 5) + ((b & c) | ((~b) & d)) + e + block[i] + 0x5A827999;
        e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    }
    for (ULONG i = 20; i < 40; i++) {
        ULONG temp = ROL(a, 5) + (b ^ c ^ d) + e + block[i] + 0x6ED9EBA1;
        e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    }
    for (ULONG i = 40; i < 60; i++) {
        ULONG temp = ROL(a, 5) + ((b & c) | (b & d) | (c & d)) + e + block[i] + 0x8F1BBCDC;
        e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    }
    for (ULONG i = 60; i < 80; i++) {
        ULONG temp = ROL(a, 5) + (b ^ c ^ d) + e + block[i] + 0xCA62C1D6;
        e = d; d = c; c = ROL(b, 30); b = a; a = temp;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d; state[4] += e;
}

static void SHA1Init(SHA1_CTX* ctx)
{
    ctx->state[0] = 0x67452301; ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE; ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
    ctx->count[0] = ctx->count[1] = 0;
}

static void SHA1Update(SHA1_CTX* ctx, const UCHAR* data, ULONG len)
{
    ULONG i, j;
    j = (ctx->count[0] >> 3) & 63;
    if ((ctx->count[0] += len << 3) < (len << 3)) ctx->count[1]++;
    ctx->count[1] += (len >> 29);
    if ((j + len) > 63) {
        i = 64 - j;
        RtlCopyMemory(&ctx->buffer[j], data, i);
        SHA1Transform(ctx->state, ctx->buffer);
        for (; i + 63 < len; i += 64) {
            SHA1Transform(ctx->state, &data[i]);
        }
        j = 0;
    } else {
        i = 0;
    }
    RtlCopyMemory(&ctx->buffer[j], &data[i], len - i);
}

static void SHA1Final(UCHAR digest[20], SHA1_CTX* ctx)
{
    UCHAR finalcount[8];
    UCHAR c = 0200;

    for (ULONG i = 0; i < 8; i++) {
        finalcount[i] = (UCHAR)((ctx->count[(i >= 4 ? 0 : 1)] >> ((3 - (i & 3)) * 8)) & 255);
    }
    SHA1Update(ctx, &c, 1);
    while ((ctx->count[0] & 504) != 448) {
        c = 0;
        SHA1Update(ctx, &c, 1);
    }
    SHA1Update(ctx, finalcount, 8);
    for (ULONG i = 0; i < 20; i++) {
        digest[i] = (UCHAR)((ctx->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
    }
}

// ================================================================
// Thumbprint comparison
// ================================================================

static int HexCharToValue(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static BOOLEAN CompareThumbprint(const UCHAR digest[20], const char* thumbprint)
{
    if (!thumbprint || thumbprint[0] == '\0') {
        return FALSE; // Empty thumbprint = reject all (safer than WinDrive default)
    }

    size_t len = 0;
    while (thumbprint[len] && len < 41) len++;
    if (len < 40) {
        SigLog("Invalid thumbprint length: %zu (expected 40)", len);
        return FALSE;
    }

    for (ULONG i = 0; i < 20; i++) {
        int high = HexCharToValue(thumbprint[i * 2]);
        int low = HexCharToValue(thumbprint[i * 2 + 1]);
        if (high < 0 || low < 0) return FALSE;
        if (digest[i] != (UCHAR)((high << 4) | low)) return FALSE;
    }
    return TRUE;
}

// ================================================================
// PKCS#7 messageDigest extraction
// ================================================================

static BOOLEAN ExtractMessageDigest(
    PUCHAR pkcs7Data, ULONG pkcs7Len,
    UCHAR* digest, ULONG* digestLen,
    BOOLEAN* isSHA256, PUCHAR expectedHash)
{
    *digestLen = 0;
    *isSHA256 = FALSE;

    const UCHAR messageDigestOID[] = { 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04 };
    const UCHAR sha256OID[] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };

    for (ULONG i = 0; i + sizeof(sha256OID) <= pkcs7Len; i++) {
        if (RtlCompareMemory(&pkcs7Data[i], sha256OID, sizeof(sha256OID)) == sizeof(sha256OID)) {
            *isSHA256 = TRUE;
            break;
        }
    }

    for (ULONG i = 0; i + sizeof(messageDigestOID) + 10 < pkcs7Len; i++) {
        if (RtlCompareMemory(&pkcs7Data[i], messageDigestOID, sizeof(messageDigestOID)) != sizeof(messageDigestOID))
            continue;

        ULONG pos = i + sizeof(messageDigestOID);

        if (pos >= pkcs7Len || pkcs7Data[pos] != 0x31) continue;
        pos++;

        if (pos >= pkcs7Len) continue;
        if (pkcs7Data[pos] & 0x80) {
            ULONG lenBytes = pkcs7Data[pos] & 0x7F;
            pos += 1 + lenBytes;
        } else {
            pos++;
        }

        if (pos >= pkcs7Len || pkcs7Data[pos] != 0x04) continue;
        pos++;

        if (pos >= pkcs7Len) continue;
        ULONG len = 0;
        if (pkcs7Data[pos] & 0x80) {
            ULONG lenBytes = pkcs7Data[pos] & 0x7F;
            if (lenBytes > 4 || pos + lenBytes >= pkcs7Len) continue;
            pos++;
            for (ULONG j = 0; j < lenBytes; j++) {
                len = (len << 8) | pkcs7Data[pos++];
            }
        } else {
            len = pkcs7Data[pos++];
        }

        if (len != 20 && len != 32) continue;
        if (pos + len > pkcs7Len) continue;

        if (expectedHash && len == 32) {
            if (RtlCompareMemory(&pkcs7Data[pos], expectedHash, 32) == 32) {
                RtlCopyMemory(digest, &pkcs7Data[pos], len);
                *digestLen = len;
                return TRUE;
            }
        } else if (!expectedHash) {
            RtlCopyMemory(digest, &pkcs7Data[pos], len);
            *digestLen = len;
            return TRUE;
        }
    }

    if (expectedHash) {
        for (ULONG i = 0; i + 32 < pkcs7Len; i++) {
            if (RtlCompareMemory(&pkcs7Data[i], expectedHash, 32) == 32) {
                RtlCopyMemory(digest, &pkcs7Data[i], 32);
                *digestLen = 32;
                *isSHA256 = TRUE;
                return TRUE;
            }
        }
    }

    SigLog("messageDigest not found in PKCS7");
    return FALSE;
}

// ================================================================
// Caller image path
// ================================================================

NTSTATUS GetCallerImagePath(PUNICODE_STRING ImagePath)
{
    NTSTATUS status;
    HANDLE processHandle = NULL;
    PEPROCESS process = NULL;
    PVOID buffer = NULL;
    ULONG returnLength = 0;

    process = IoGetCurrentProcess();
    if (!process) return STATUS_UNSUCCESSFUL;

    status = ObOpenObjectByPointer(
        process, OBJ_KERNEL_HANDLE, NULL, 0x0400,
        *PsProcessType, KernelMode, &processHandle);
    if (!NT_SUCCESS(status)) {
        SigLog("ObOpenObjectByPointer failed: 0x%08X", status);
        return status;
    }

    status = ZwQueryInformationProcess(
        processHandle, ProcessImageFileName, NULL, 0, &returnLength);
    if (status != STATUS_INFO_LENGTH_MISMATCH || returnLength == 0) {
        ZwClose(processHandle);
        return STATUS_UNSUCCESSFUL;
    }

    buffer = SigAllocMem(returnLength);
    if (!buffer) {
        ZwClose(processHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwQueryInformationProcess(
        processHandle, ProcessImageFileName, buffer, returnLength, &returnLength);
    if (NT_SUCCESS(status)) {
        PUNICODE_STRING srcPath = (PUNICODE_STRING)buffer;
        if (ImagePath->MaximumLength >= srcPath->Length + sizeof(WCHAR)) {
            RtlCopyMemory(ImagePath->Buffer, srcPath->Buffer, srcPath->Length);
            ImagePath->Length = srcPath->Length;
            ImagePath->Buffer[ImagePath->Length / sizeof(WCHAR)] = L'\0';
            SigLog("Caller image path: %wZ", ImagePath);
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
    }

    SigFreeMem(buffer);
    ZwClose(processHandle);
    return status;
}

// ================================================================
// WIN_CERTIFICATE
// ================================================================

typedef struct _WIN_CERTIFICATE {
    ULONG dwLength;
    USHORT wRevision;
    USHORT wCertificateType;
    UCHAR bCertificate[1];
} WIN_CERTIFICATE, *PWIN_CERTIFICATE;

#define WIN_CERT_TYPE_PKCS_SIGNED_DATA 0x0002

// ================================================================
// Authenticode hash calculation
// ================================================================

static BOOLEAN CalculateAuthenticodeHash(
    PVOID fileBuffer, ULONG fileSize,
    UCHAR hash[32], BOOLEAN* isSHA256)
{
    *isSHA256 = FALSE;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBuffer;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    if (dosHeader->e_lfanew < 0 ||
        (ULONG)dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) > fileSize)
        return FALSE;

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)fileBuffer + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    ULONG checksumOffset = 0;
    ULONG securityDirOffset = 0;
    ULONG securityDirVA = 0;

    if (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        PIMAGE_NT_HEADERS64 nt64 = (PIMAGE_NT_HEADERS64)ntHeaders;
        checksumOffset = dosHeader->e_lfanew + 24 + 64;
        securityDirOffset = dosHeader->e_lfanew + 24 + 144;
        securityDirVA = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
    } else if (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        checksumOffset = dosHeader->e_lfanew + 24 + 64;
        securityDirOffset = dosHeader->e_lfanew + 24 + 128;
        securityDirVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
    } else {
        return FALSE;
    }

    ULONG hashEnd = securityDirVA > 0 ? securityDirVA : fileSize;

    if (checksumOffset + 4 > fileSize ||
        securityDirOffset + 8 > fileSize ||
        hashEnd > fileSize ||
        checksumOffset >= securityDirOffset ||
        securityDirOffset + 8 > hashEnd)
        return FALSE;

    SHA256_CTX ctx;
    SHA256Init(&ctx);
    SHA256Update(&ctx, (PUCHAR)fileBuffer, checksumOffset);
    SHA256Update(&ctx, (PUCHAR)fileBuffer + checksumOffset + 4, securityDirOffset - checksumOffset - 4);
    SHA256Update(&ctx, (PUCHAR)fileBuffer + securityDirOffset + 8, hashEnd - securityDirOffset - 8);
    SHA256Final(hash, &ctx);
    *isSHA256 = TRUE;

    return TRUE;
}

// ================================================================
// PE signature verification from file
// ================================================================

static SIGNATURE_STATUS VerifyPESignatureFromFile(PUNICODE_STRING FilePath)
{
    NTSTATUS status;
    HANDLE fileHandle = NULL;
    OBJECT_ATTRIBUTES objAttr = { 0 };
    IO_STATUS_BLOCK ioStatus = { 0 };
    PVOID fileBuffer = NULL;
    FILE_STANDARD_INFORMATION fileInfo = { 0 };

    InitializeObjectAttributes(&objAttr, FilePath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = ZwCreateFile(
        &fileHandle, GENERIC_READ | SYNCHRONIZE, &objAttr, &ioStatus,
        NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);
    if (!NT_SUCCESS(status)) {
        SigLog("ZwCreateFile failed: 0x%08X", status);
        return SignatureError;
    }

    status = ZwQueryInformationFile(fileHandle, &ioStatus, &fileInfo, sizeof(fileInfo), FileStandardInformation);
    if (!NT_SUCCESS(status)) {
        ZwClose(fileHandle);
        return SignatureError;
    }

    LARGE_INTEGER fileSize = fileInfo.EndOfFile;
    if (fileSize.QuadPart > 100 * 1024 * 1024 || fileSize.QuadPart < 256) {
        ZwClose(fileHandle);
        return SignatureError;
    }

    fileBuffer = SigAllocMem((SIZE_T)fileSize.QuadPart);
    if (!fileBuffer) {
        ZwClose(fileHandle);
        return SignatureError;
    }

    LARGE_INTEGER offset = { 0 };
    status = ZwReadFile(fileHandle, NULL, NULL, NULL, &ioStatus,
        fileBuffer, (ULONG)fileSize.QuadPart, &offset, NULL);
    ZwClose(fileHandle);

    if (!NT_SUCCESS(status)) {
        SigFreeMem(fileBuffer);
        return SignatureError;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBuffer;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        SigFreeMem(fileBuffer);
        return SignatureInvalid;
    }

    if (dosHeader->e_lfanew < 0 ||
        (ULONG)dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) > (ULONG)fileSize.QuadPart) {
        SigFreeMem(fileBuffer);
        return SignatureInvalid;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)fileBuffer + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        SigFreeMem(fileBuffer);
        return SignatureInvalid;
    }

    PIMAGE_DATA_DIRECTORY securityDir;
    if (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        PIMAGE_NT_HEADERS64 nt64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)fileBuffer + dosHeader->e_lfanew);
        securityDir = &nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
    } else {
        securityDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
    }

    if (securityDir->VirtualAddress == 0 || securityDir->Size == 0) {
        SigLog("No security directory - file is not signed");
        SigFreeMem(fileBuffer);
        return SignatureNotFound;
    }

    ULONG certOffset = securityDir->VirtualAddress;
    if ((LONGLONG)certOffset + securityDir->Size > fileSize.QuadPart) {
        SigLog("SecVA out of range, scanning file tail");
        certOffset = 0;
        ULONG scanStart = (ULONG)fileSize.QuadPart > 0x1000 ? (ULONG)fileSize.QuadPart - 0x1000 : 0;
        for (ULONG i = scanStart; i + 8 < (ULONG)fileSize.QuadPart; i++) {
            PUCHAR p = (PUCHAR)fileBuffer + i;
            ULONG  dwLen = *(ULONG*)p;
            USHORT wType = *(USHORT*)(p + 6);
            if (wType == WIN_CERT_TYPE_PKCS_SIGNED_DATA &&
                dwLen > 8 && dwLen < 0x4000 &&
                (LONGLONG)i + dwLen <= fileSize.QuadPart &&
                p[8] == 0x30) {
                certOffset = i;
                SigLog("Found WIN_CERTIFICATE at 0x%X", certOffset);
                break;
            }
        }
        if (certOffset == 0) {
            SigFreeMem(fileBuffer);
            return SignatureInvalid;
        }
    }

    PWIN_CERTIFICATE cert = (PWIN_CERTIFICATE)((ULONG_PTR)fileBuffer + certOffset);
    if (cert->wCertificateType != WIN_CERT_TYPE_PKCS_SIGNED_DATA) {
        SigFreeMem(fileBuffer);
        return SignatureInvalid;
    }

    ULONG maxCertLen = (ULONG)fileSize.QuadPart - certOffset;
    if (cert->dwLength < sizeof(WIN_CERTIFICATE) || cert->dwLength > maxCertLen) {
        SigFreeMem(fileBuffer);
        return SignatureInvalid;
    }

    PUCHAR pkcs7Data = cert->bCertificate;
    ULONG pkcs7Len = cert->dwLength - FIELD_OFFSET(WIN_CERTIFICATE, bCertificate);

    if (pkcs7Len < 4 || pkcs7Data[0] != 0x30) {
        SigFreeMem(fileBuffer);
        return SignatureInvalid;
    }

    // Step 1: Calculate Authenticode hash
    UCHAR authenticodeHash[32];
    BOOLEAN isAuthSHA256 = FALSE;
    if (!CalculateAuthenticodeHash(fileBuffer, (ULONG)fileSize.QuadPart, authenticodeHash, &isAuthSHA256)) {
        SigFreeMem(fileBuffer);
        return SignatureInvalid;
    }

    // Step 2: Extract messageDigest from PKCS7
    UCHAR messageDigest[32];
    ULONG messageDigestLen = 0;
    BOOLEAN isPkcs7SHA256 = FALSE;
    if (!ExtractMessageDigest(pkcs7Data, pkcs7Len, messageDigest, &messageDigestLen, &isPkcs7SHA256, authenticodeHash)) {
        SigFreeMem(fileBuffer);
        return SignatureInvalid;
    }

    // Step 3: Compare hashes
    if (messageDigestLen == 32) {
        if (RtlCompareMemory(authenticodeHash, messageDigest, 32) != 32) {
            SigLog("Authenticode SHA256 hash mismatch - file has been tampered");
            SigFreeMem(fileBuffer);
            return SignatureInvalid;
        }
        SigLog("Authenticode SHA256 hash verified");
    } else {
        SigFreeMem(fileBuffer);
        return SignatureInvalid;
    }

    // Step 4: Verify certificate thumbprint
    PUCHAR certDerData = NULL;
    ULONG certDerLen = 0;

    for (ULONG i = 0; i + 4 <= pkcs7Len; i++) {
        if (pkcs7Data[i] != 0x30 || pkcs7Data[i + 1] != 0x82) continue;

        ULONG cl = ((ULONG)pkcs7Data[i + 2] << 8 | pkcs7Data[i + 3]) + 4;
        if (cl < 64 || cl >= pkcs7Len || i + cl > pkcs7Len) continue;

        SHA1_CTX tmpCtx;
        UCHAR tmpThumb[20];
        SHA1Init(&tmpCtx);
        SHA1Update(&tmpCtx, &pkcs7Data[i], cl);
        SHA1Final(tmpThumb, &tmpCtx);

        if (CompareThumbprint(tmpThumb, TRUSTED_CERT_THUMBPRINT)) {
            certDerData = &pkcs7Data[i];
            certDerLen = cl;
            SigLog("Found matching cert at pkcs7+0x%X len=%u", i, cl);
            break;
        }
    }

    if (!certDerData || certDerLen == 0) {
        SigLog("No matching certificate found in PKCS#7");
        SigFreeMem(fileBuffer);
        return SignatureUntrusted;
    }

    SigLog("Full Authenticode verification passed");
    SigFreeMem(fileBuffer);
    return SignatureValid;
}

// ================================================================
// Public API
// ================================================================

SIGNATURE_STATUS VerifyCallerSignature(VOID)
{
    WCHAR pathBuffer[520] = { 0 };
    UNICODE_STRING imagePath = { 0 };

    imagePath.Buffer = pathBuffer;
    imagePath.MaximumLength = sizeof(pathBuffer);
    imagePath.Length = 0;

    NTSTATUS status = GetCallerImagePath(&imagePath);
    if (!NT_SUCCESS(status)) {
        SigLog("GetCallerImagePath failed: 0x%08X", status);
        return SignatureError;
    }

    return VerifyFileSignature(&imagePath);
}

SIGNATURE_STATUS VerifyFileSignature(PUNICODE_STRING FilePath)
{
    if (!FilePath || FilePath->Length == 0) return SignatureError;
    SigLog("Verifying signature for: %wZ", FilePath);
    return VerifyPESignatureFromFile(FilePath);
}

NTSTATUS InitializeSignatureVerification(VOID)
{
    SigLog("Signature verification initialized (thumbprint mode)");
    return STATUS_SUCCESS;
}

VOID CleanupSignatureVerification(VOID)
{
    SigLog("Signature verification cleaned up");
}
