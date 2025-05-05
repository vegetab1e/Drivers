#include <fltKernel.h>

#include <iso646.h>

#include "tools.h"

static UNICODE_STRING SERVER_PORT_NAME = RTL_CONSTANT_STRING(L"\\FileBlockerFilterPort");

typedef struct _FILE_BLOCKER_PROPERTIES
{
    PFLT_FILTER filter_handle;
#ifdef UNDER_CONSTRUCTION
    PFLT_PORT   server_port;
    PFLT_PORT   client_port;
#endif
} FILE_BLOCKER_PROPERTIES, *PFILE_BLOCKER_PROPERTIES;

DRIVER_INITIALIZE driverEntry;
static VOID driverUnload(_In_ PDRIVER_OBJECT driver_object);

static NTSTATUS filterUnloadCallback(_In_ FLT_FILTER_UNLOAD_FLAGS flags);
static NTSTATUS filterLoadCallback(_In_ PCFLT_RELATED_OBJECTS filter_objects,
                                   _In_ FLT_INSTANCE_SETUP_FLAGS flags,
                                   _In_ DEVICE_TYPE  volume_device_yype,
                                   _In_ FLT_FILESYSTEM_TYPE  volume_filesystem_type);

static FLT_PREOP_CALLBACK_STATUS preOperationCallback(_Inout_ PFLT_CALLBACK_DATA data,
                                                      _In_ PCFLT_RELATED_OBJECTS filter_objects,
                                                      _Out_ PVOID* completion_context);

#ifdef UNDER_CONSTRUCTION
static NTSTATUS
messageCallback(_In_ PVOID connection_cookie,
                _In_reads_bytes_opt_(input_buffer_size) PVOID input_buffer,
                _In_ ULONG input_buffer_size,
                _Out_writes_bytes_to_opt_(output_buffer_size, *output_buffer_length) PVOID output_buffer,
                _In_ ULONG output_buffer_size,
                _Out_ PULONG output_buffer_length)
{
    UNREFERENCED_PARAMETER(connection_cookie);
    UNREFERENCED_PARAMETER(input_buffer);
    UNREFERENCED_PARAMETER(input_buffer_size);
    UNREFERENCED_PARAMETER(output_buffer);
    UNREFERENCED_PARAMETER(output_buffer_size);

    PAGED_CODE();

    KdPrint(("messageCallback() called\n"));

    *output_buffer_length = 0;

    return STATUS_SUCCESS;
}

static NTSTATUS
connectCallback(_In_ PFLT_PORT client_port,
                _In_ PVOID server_port_cookie,
                _In_reads_bytes_(size_of_context) PVOID connection_context,
                _In_ ULONG size_of_context,
                _Flt_ConnectionCookie_Outptr_ PVOID* connection_cookie)
{
    UNREFERENCED_PARAMETER(server_port_cookie);
    UNREFERENCED_PARAMETER(connection_context);
    UNREFERENCED_PARAMETER(size_of_context);
    UNREFERENCED_PARAMETER(connection_cookie);

    PAGED_CODE();

    KdPrint(("connectCallback() called\n"));

    FLT_ASSERT(not file_blocker_props.client_port);
    file_blocker_props.client_port = client_port;

    return STATUS_SUCCESS;
}

static VOID
disconnectCallback(_In_opt_ PVOID connection_cookie)
{
    UNREFERENCED_PARAMETER(connection_cookie);

    PAGED_CODE();

    KdPrint(("disconnectCallback() called\n"));

    FltCloseClientPort(file_blocker_props.filter_handle,
                       &file_blocker_props.client_port);
}
#endif

static FILE_BLOCKER_PROPERTIES file_blocker_props;

static CONST FLT_OPERATION_REGISTRATION callbacks[] = {
    { IRP_MJ_CREATE,
      0,
      preOperationCallback,
      NULL },

    { IRP_MJ_SET_INFORMATION,
      0,
      preOperationCallback,
      NULL },

    { IRP_MJ_OPERATION_END }
};

static CONST FLT_CONTEXT_REGISTRATION contexts[] = {
    { FLT_CONTEXT_END }
};

static CONST FLT_REGISTRATION filter_registration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    contexts,
    callbacks,
    filterUnloadCallback,
    filterLoadCallback,
    NULL,
    NULL,
    NULL
};

NTSTATUS driverEntry(_In_ PDRIVER_OBJECT driver_object,
                     _In_ PUNICODE_STRING registry_path)
{
    UNREFERENCED_PARAMETER(registry_path);

    driver_object->DriverUnload = driverUnload;

    if (not initializeFileBlocker())
    {
        KdPrint(("Initialization failed\n"));
        return STATUS_DEVICE_CONFIGURATION_ERROR;
    }

    NTSTATUS status = FltRegisterFilter(driver_object,
                                        &filter_registration,
                                        &file_blocker_props.filter_handle);
    if (not NT_SUCCESS(status))
    {
        KdPrint(("Failed to register filter\n"));
        return status;
    }

    KdPrint(("Filter registered\n"));

#ifdef UNDER_CONSTRUCTION
    PSECURITY_DESCRIPTOR security_descriptor;
    status = FltBuildDefaultSecurityDescriptor(&security_descriptor, FLT_PORT_ALL_ACCESS);
    if (not NT_SUCCESS(status))
    {
        KdPrint(("Failed to build security descriptor\n"));
        return status;
    }

    OBJECT_ATTRIBUTES object_attributes;
    InitializeObjectAttributes(&object_attributes,
                               &SERVER_PORT_NAME,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL,
                               security_descriptor);

    status = FltCreateCommunicationPort(file_blocker_props.filter_handle,
                                        &file_blocker_props.server_port,
                                        &object_attributes,
                                        NULL,
                                        connectCallback,
                                        disconnectCallback,
                                        messageCallback,
                                        1);

    FltFreeSecurityDescriptor(security_descriptor);

    if (not NT_SUCCESS(status))
    {
        KdPrint(("Failed to create communication port\n"));
        return status;
    }
#endif

    status = FltStartFiltering(file_blocker_props.filter_handle);
    if (not NT_SUCCESS(status))
    {
        KdPrint(("Failed to start filtering\n"));

        FltUnregisterFilter(file_blocker_props.filter_handle);

        KdPrint(("Filter unregistered\n"));
        return status;
    }

    KdPrint(("Filtering started\n"));
    KdPrint(("Driver loaded\n"));
    return status;
}

static VOID driverUnload(_In_ PDRIVER_OBJECT driver_object)
{
    UNREFERENCED_PARAMETER(driver_object);

#ifdef UNDER_CONSTRUCTION
    if (file_blocker_props.server_port)
        FltCloseCommunicationPort(file_blocker_props.server_port);
#endif

    if (file_blocker_props.filter_handle)
    {
        FltUnregisterFilter(file_blocker_props.filter_handle);

        KdPrint(("Filter unregistered\n"));
    }

    uninitializeFileBlocker();

    KdPrint(("Driver unloaded\n"));
}

static NTSTATUS filterUnloadCallback(_In_ FLT_FILTER_UNLOAD_FLAGS flags)
{
    UNREFERENCED_PARAMETER(flags);

    PAGED_CODE();

    KdPrint(("Filter unloaded\n"));
    return STATUS_SUCCESS;
}

static NTSTATUS filterLoadCallback(_In_ PCFLT_RELATED_OBJECTS filter_objects,
                                   _In_ FLT_INSTANCE_SETUP_FLAGS flags,
                                   _In_ DEVICE_TYPE  volume_device_type,
                                   _In_ FLT_FILESYSTEM_TYPE  volume_filesystem_type)
{
    UNREFERENCED_PARAMETER(filter_objects);
    UNREFERENCED_PARAMETER(flags);

    PAGED_CODE();

    if (volume_device_type not_eq FILE_DEVICE_DISK_FILE_SYSTEM)
    {
        KdPrint(("Filter not loaded (device/filesystem types): %lu/%i\n",
                 volume_device_type, volume_filesystem_type));
        return STATUS_FLT_DO_NOT_ATTACH;
    }

    KdPrint(("Filter loaded (device/filesystem types): %lu/%i\n",
             volume_device_type, volume_filesystem_type));
    return STATUS_SUCCESS;
}

static FLT_PREOP_CALLBACK_STATUS preOperationCallback(_Inout_ PFLT_CALLBACK_DATA data,
                                                      _In_ PCFLT_RELATED_OBJECTS filter_objects,
                                                      _Out_ PVOID* completion_context)
{
    PAGED_CODE();

    if (not data or not filter_objects)
    {
        KdPrint(("WARNING: Null pointer catched!\n"));
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

#ifndef NDEBUG
    if (not FLT_IS_IRP_OPERATION(data))
    {
        KdPrint(("WARNING: This is not IRP operation!\n"));
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
#endif

    if (completion_context)
        *completion_context = NULL;

    if (data->RequestorMode == KernelMode)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    PFLT_IO_PARAMETER_BLOCK io_parameter_block = data->Iopb;
#ifdef PARANOID_MODE
    if (not io_parameter_block)
    {
        KdPrint(("WARNING: Iopb is null!\n"));
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
#endif
    PFLT_PARAMETERS parameters = &io_parameter_block->Parameters;
    if (io_parameter_block->MajorFunction == IRP_MJ_SET_INFORMATION)
    {
        CONST FILE_INFORMATION_CLASS file_information_class = parameters->SetFileInformation.FileInformationClass;
        if (file_information_class not_eq FileRenameInformation and
            file_information_class not_eq FileDispositionInformation)
            return FLT_PREOP_SUCCESS_NO_CALLBACK;

        if (file_information_class == FileDispositionInformation)
        {
#ifdef PARANOID_MODE
            if (not parameters->SetFileInformation.InfoBuffer)
            {
                KdPrint(("WARNING: InfoBuffer is null!\n"));
                return FLT_PREOP_SUCCESS_NO_CALLBACK;
            }
#endif
            // Удаление файла в корзину (второй этап, поздно блокировать)
            if (not ((PFILE_DISPOSITION_INFORMATION)parameters->SetFileInformation.InfoBuffer)->DeleteFile)
                return FLT_PREOP_SUCCESS_NO_CALLBACK;

            // Удаление файла в корзину (первый этап, можно заблокировать)
            KdPrint(("This is delete operation\n"));
        }
        else
        {
#ifdef PARANOID_MODE
            if (not parameters->SetFileInformation.InfoBuffer)
            {
                KdPrint(("WARNING: InfoBuffer is null!\n"));
                return FLT_PREOP_SUCCESS_NO_CALLBACK;
            }
#endif
            // Удаление файла в корзину (третий этап, поздно блокировать)
            PFILE_RENAME_INFORMATION rename_info = (PFILE_RENAME_INFORMATION)parameters->SetFileInformation.InfoBuffer;
            if (not rename_info->RootDirectory)
            {
                if (isRecycleBinPath(rename_info->FileName, rename_info->FileNameLength))
                    return FLT_PREOP_SUCCESS_NO_CALLBACK;
            }
            else
            {
#ifdef PARANOID_MODE
                if (not parameters->SetFileInformation.ParentOfTarget)
                {
                    KdPrint(("WARNING: ParentOfTarget is null!\n"));
                    return FLT_PREOP_SUCCESS_NO_CALLBACK;
                }
#endif
                if (isRecycleBinPath(parameters->SetFileInformation.ParentOfTarget->FileName.Buffer,
                                     parameters->SetFileInformation.ParentOfTarget->FileName.Length))
                    return FLT_PREOP_SUCCESS_NO_CALLBACK;
            }

            KdPrint(("This is rename or link operation\n"));
        }

        BOOLEAN is_directory = FALSE;
        NTSTATUS status = STATUS_INVALID_PARAMETER;
        if (not (filter_objects->FileObject && filter_objects->Instance) ||
            not NT_SUCCESS(status = FltIsDirectory(filter_objects->FileObject,
                                                   filter_objects->Instance,
                                                   &is_directory)))
        {
            KdPrint(("Failed to check file object type: 0x%08X\n", status));
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        if (is_directory)
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    else if (io_parameter_block->MajorFunction == IRP_MJ_CREATE)
    {
        // The high 8 bits contains the CreateDisposition values.
        if ((parameters->Create.Options >> 24) not_eq FILE_OPEN)
            return FLT_PREOP_SUCCESS_NO_CALLBACK;

        // The low 24 bits contains CreateOptions flag values.
        CONST ULONG create_options = parameters->Create.Options & 0x00FFFFFF;
        if (not (create_options & FILE_NON_DIRECTORY_FILE) or  // не файл
            not (create_options & FILE_SEQUENTIAL_ONLY))       // не копирование
            return FLT_PREOP_SUCCESS_NO_CALLBACK;

        KdPrint(("This is copy operation\n"));
    }
    else
    {
        KdPrint(("This operation is not blocked\n"));
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Этот фрагмент кода используется для отлдаки и периодически
    // перемещается внутри функции, поэтому локальные переменные
    // в нём не используются, а проверки могут быть избыточны.
#ifndef NDEBUG
    KdPrint(("Callback called: 0x%08X\n",
             data->Iopb->MajorFunction));

    if (data->Iopb->TargetFileObject)
        KdPrint(("[FLT_CALLBACK_DATA] FileName: %wZ\n",
                 data->Iopb->TargetFileObject->FileName));
    if (filter_objects->FileObject)
        KdPrint(("[FLT_RELATED_OBJECTS] FileName: %wZ\n",
                 filter_objects->FileObject->FileName));
    
    if (data->Iopb->MajorFunction == IRP_MJ_CREATE)
    {
        // The high 8 bits contains the CreateDisposition values.
        KdPrint(("[IRP_MJ_CREATE] CreateDisposition: 0x%08X\n",
                 data->Iopb->Parameters.Create.Options >> 24));
        // The low 24 bits contains CreateOptions flag values.
        KdPrint(("[IRP_MJ_CREATE] CreateOptions: 0x%08X\n",
                 data->Iopb->Parameters.Create.Options & 0x00FFFFFF));
    }
    else
    if (data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION)
    {
        KdPrint(("[IRP_MJ_SET_INFORMATION] FileInformationClass: %i\n",
                 data->Iopb->Parameters.SetFileInformation.FileInformationClass));
    }
#endif

    PFILE_OBJECT file_object = io_parameter_block->TargetFileObject;
    if (not file_object)
    {
        KdPrint(("Failed to get file object\n"));
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (not isExtensionBlocked(&file_object->FileName))
    {
        KdPrint(("This file extension is not blocked\n"));
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    PFLT_FILE_NAME_INFORMATION file_name_info = NULL;
    NTSTATUS status = FltGetFileNameInformation(data,
                                                FLT_FILE_NAME_NORMALIZED,
                                                &file_name_info);
#ifdef PARANOID_MODE
    if (not file_name_info)
    {
        KdPrint(("WARNING: FltGetFileNameInformation() out parameter is null!\n"));
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
#endif
    if (not NT_SUCCESS(status))
    {
        KdPrint(("Failed to get file name info: 0x%08X\n", status));
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (isTextBlocked(file_name_info->Name))
    {
        KdPrint(("Blocking operation on file: %wZ\n", file_name_info->Name));

        FltReleaseFileNameInformation(file_name_info);
                
        data->IoStatus.Status = STATUS_ACCESS_DENIED;
        data->IoStatus.Information = 0;

        return FLT_PREOP_COMPLETE;
    }

    KdPrint(("This content is not blocked\n"));

    FltReleaseFileNameInformation(file_name_info);

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
