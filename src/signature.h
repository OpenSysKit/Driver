#pragma once

//
// PE Signature Verification for OpenSysKit Driver
// Ported from WinDrive/DriverLoader
// Uses certificate SHA1 thumbprint for verification
//

#include <ntddk.h>

// Certificate: WinDriverLoader (O=Admilk)
// SHA1 thumbprint of the trusted signing certificate (40 hex chars, uppercase)
#define TRUSTED_CERT_THUMBPRINT "E723BD5F5C61A0541945A3640F3FEFFE3F090D69"

#define SIGNATURE_TAG 'GiSK'

typedef enum _SIGNATURE_STATUS {
    SignatureValid = 0,
    SignatureNotFound,
    SignatureInvalid,
    SignatureUntrusted,
    SignatureExpired,
    SignatureError
} SIGNATURE_STATUS;

SIGNATURE_STATUS VerifyCallerSignature(VOID);
SIGNATURE_STATUS VerifyFileSignature(PUNICODE_STRING FilePath);
NTSTATUS GetCallerImagePath(PUNICODE_STRING ImagePath);
NTSTATUS InitializeSignatureVerification(VOID);
VOID CleanupSignatureVerification(VOID);
