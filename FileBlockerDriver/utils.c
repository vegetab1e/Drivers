#ifndef NDEBUG
#include <fltKernel.h>
#endif
#include <ntddk.h>
#include <ntstrsafe.h>

#include <iso646.h>

#include "utils.h"

#ifndef NDEBUG
#define POOL_TAG '1gaT'
#endif

#define MAX_STRING_LEN  256U

#define OS_MAJOR_VERSION    10UL
#define OS_MINOR_VERSION     0UL
#define OS_BUILD_NUMBER  19041UL

BOOLEAN checkOsVersion()
{
    RTL_OSVERSIONINFOW os_version_info = {
        .dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW)
    };

    NTSTATUS status = RtlGetVersion(&os_version_info);
    if (not NT_SUCCESS(status))
    {
        KdPrint(("Failed to get OS version: 0x%08X\n", status));
        return FALSE;
    }

    CHAR buffer[MAX_STRING_LEN * sizeof(WCHAR)];
    UNICODE_STRING os_version = {
        .Buffer = (PWCHAR)buffer,
        .Length = 0,
        .MaximumLength = sizeof(buffer)
    };

    status = RtlUnicodeStringPrintf(&os_version,
                                    L"%lu.%lu.%lu",
                                    os_version_info.dwMajorVersion,
                                    os_version_info.dwMinorVersion,
                                    os_version_info.dwBuildNumber);
    if (not NT_SUCCESS(status))
    {
        KdPrint(("Failed to create formatted string: 0x%08X\n", status));
        return FALSE;
    }

    KdPrint(("OS version: %wZ\n", &os_version));

    if (os_version_info.dwMajorVersion != OS_MAJOR_VERSION or
        os_version_info.dwMinorVersion != OS_MINOR_VERSION or
        os_version_info.dwBuildNumber   < OS_BUILD_NUMBER)
        return FALSE;

    return TRUE;
}

#ifndef NDEBUG
_Use_decl_annotations_
VOID printVolumeName(_In_ PFLT_VOLUME volume)
{
    if (not volume)
    {
        KdPrint(("Invalid parameter\n"));
        return;
    }

    ULONG volume_name_size = 0;
    NTSTATUS status = FltGetVolumeName(volume,
                                       NULL,
                                       &volume_name_size);
    if (not NT_SUCCESS(status) &&
        status != STATUS_BUFFER_TOO_SMALL)
    {
        KdPrint(("Failed to get volume name: 0x%08X\n", status));
        return;
    }

    UNICODE_STRING volume_name = {
        .Buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                  volume_name_size,
                                  POOL_TAG),
        .Length = 0,
        .MaximumLength = (USHORT)volume_name_size
    };

    if (not volume_name.Buffer)
    {
        KdPrint(("Failed to allocate memory\n"));
        return;
    }

    status = FltGetVolumeName(volume,
                              &volume_name,
                              NULL);
    if (not NT_SUCCESS(status))
    {
        KdPrint(("Failed to get volume name: 0x%08X\n", status));
    
        ExFreePool(volume_name.Buffer);
        
        return;
    }

    KdPrint(("Volume name: %wZ\n", &volume_name));

    ExFreePool(volume_name.Buffer);
}
#endif
