#include "driver.h"

static OB_PREOP_CALLBACK_STATUS OnPreOpenProcess(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInfo
)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (OperationInfo->KernelHandle) {
        return OB_PREOP_SUCCESS;
    }

    PEPROCESS targetProcess = (PEPROCESS)OperationInfo->Object;
    ULONG targetPid = (ULONG)(ULONG_PTR)PsGetProcessId(targetProcess);

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_DriverContext.ProtectLock, &oldIrql);

    BOOLEAN isProtected = FALSE;
    for (ULONG i = 0; i < g_DriverContext.ProtectedPidCount; i++) {
        if (g_DriverContext.ProtectedPids[i] == targetPid) {
            isProtected = TRUE;
            break;
        }
    }

    KeReleaseSpinLock(&g_DriverContext.ProtectLock, oldIrql);

    if (isProtected) {
        // 剥离终止和挂起权限
        if (OperationInfo->Operation == OB_OPERATION_HANDLE_CREATE) {
            OperationInfo->Parameters->CreateHandleInformation.DesiredAccess &=
                ~(PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME);
        } else if (OperationInfo->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
            OperationInfo->Parameters->DuplicateHandleInformation.DesiredAccess &=
                ~(PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME);
        }
    }

    return OB_PREOP_SUCCESS;
}

// ObRegisterCallbacks 需要一个有效的 Altitude 字符串
static UNICODE_STRING g_Altitude = RTL_CONSTANT_STRING(L"321000");

NTSTATUS RegisterProtectCallbacks()
{
    OB_CALLBACK_REGISTRATION cbReg;
    OB_OPERATION_REGISTRATION opReg;

    RtlZeroMemory(&cbReg, sizeof(cbReg));
    RtlZeroMemory(&opReg, sizeof(opReg));

    opReg.ObjectType = PsProcessType;
    opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opReg.PreOperation = OnPreOpenProcess;
    opReg.PostOperation = NULL;

    cbReg.Version = OB_FLT_REGISTRATION_VERSION;
    cbReg.OperationRegistrationCount = 1;
    cbReg.Altitude = g_Altitude;
    cbReg.RegistrationContext = NULL;
    cbReg.OperationRegistration = &opReg;

    return ObRegisterCallbacks(&cbReg, &g_DriverContext.ObCallbackHandle);
}

void UnregisterProtectCallbacks()
{
    if (g_DriverContext.ObCallbackHandle) {
        ObUnRegisterCallbacks(g_DriverContext.ObCallbackHandle);
        g_DriverContext.ObCallbackHandle = NULL;
    }
}
