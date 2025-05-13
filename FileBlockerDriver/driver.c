#include <fltKernel.h>

#include <iso646.h>

#include "tools.h"
#include "utils.h"

#define POOL_TAG '1gaT'

#define RX_BUFFER_SIZE    1024U
#define MAX_FLT_INSTANCES   64U

static UNICODE_STRING SERVER_PORT_NAME = RTL_CONSTANT_STRING(L"\\FileBlockerFilterPort");

typedef struct _FILE_BLOCKER_PROPERTIES
{
    PKTHREAD thread;
    PFAST_MUTEX mutex;
    PFLT_FILTER filter;
    USHORT num_flt_instances;
    PFLT_INSTANCE flt_instances[MAX_FLT_INSTANCES];
    PFLT_PORT server_port;
    PFLT_PORT client_port;
} FILE_BLOCKER_PROPERTIES, *PFILE_BLOCKER_PROPERTIES;

static FILE_BLOCKER_PROPERTIES fb_props;

DRIVER_INITIALIZE driverEntry;
DRIVER_UNLOAD driverUnload;

static NTSTATUS
FLTAPI filterUnloadCallback(_In_ FLT_FILTER_UNLOAD_FLAGS flags);

static NTSTATUS
FLTAPI instanceSetupCallback(_In_ PCFLT_RELATED_OBJECTS related_objects,
                             _In_ FLT_INSTANCE_SETUP_FLAGS setup_flags,
                             _In_ DEVICE_TYPE  device_yype,
                             _In_ FLT_FILESYSTEM_TYPE  filesystem_type);

#ifndef DISABLE_MANUAL_DETACH
static NTSTATUS
FLTAPI instanceQueryTeardownCallback(_In_ PCFLT_RELATED_OBJECTS related_objects,
                                     _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS teardown_flags);
#endif

static FLT_PREOP_CALLBACK_STATUS
FLTAPI preOperationCallback(_Inout_ PFLT_CALLBACK_DATA data,
                            _In_ PCFLT_RELATED_OBJECTS related_objects,
                            _Outptr_result_maybenull_ PVOID* completion_context);

static NTSTATUS
FLTAPI messageCallback(_In_opt_ PVOID connection_cookie,
                       _In_reads_bytes_opt_(input_buffer_size) PVOID input_buffer,
                       _In_ ULONG input_buffer_size,
                       _Out_writes_bytes_to_opt_(output_buffer_size, *output_buffer_length) PVOID output_buffer,
                       _In_ ULONG output_buffer_size,
                       _Out_ PULONG output_buffer_length)
{
    UNREFERENCED_PARAMETER(connection_cookie);
    UNREFERENCED_PARAMETER(output_buffer);
    UNREFERENCED_PARAMETER(output_buffer_size);

    PAGED_CODE();

    KdPrint(("messageCallback() called\n"));

    *output_buffer_length = 0;

    if (not input_buffer or
        not input_buffer_size)
    {
        KdPrint(("Empty message\n"));
        return STATUS_SUCCESS;
    }

    CHAR buffer[RX_BUFFER_SIZE];
    ULONG length = sizeof(buffer);
    RtlZeroMemory(buffer, length);

    CONST NTSTATUS status = RtlUTF8ToUnicodeN((PWCHAR)buffer,
                                              length,
                                              &length,
                                              input_buffer,
                                              input_buffer_size);
    if (not NT_SUCCESS(status))
    {
        KdPrint(("Failed to convert string: 0x%08X\n", status));
        return STATUS_SUCCESS;
    }

    CONST UNICODE_STRING message = {
        .Buffer = (PWCHAR)buffer,
        .Length = (USHORT)length,
        .MaximumLength = (USHORT)length
    };
    
    KdPrint(("Message: %wZ\n", &message));

    // TODO: Реализовать управление
    // фильтром из консоли (в UM)
    (void)message;

    return STATUS_SUCCESS;
}

static NTSTATUS
FLTAPI connectCallback(_In_ PFLT_PORT client_port,
                       _In_opt_ PVOID server_port_cookie,
                       _In_reads_bytes_opt_(size_of_context) PVOID connection_context,
                       _In_ ULONG size_of_context,
                       _Outptr_result_maybenull_ PVOID* connection_cookie)
{
    UNREFERENCED_PARAMETER(server_port_cookie);
    UNREFERENCED_PARAMETER(connection_context);
    UNREFERENCED_PARAMETER(size_of_context);

    PAGED_CODE();

    KdPrint(("connectCallback() called\n"));

    *connection_cookie = NULL;

    FLT_ASSERT(not fb_props.client_port);
    fb_props.client_port = client_port;

    return STATUS_SUCCESS;
}

static VOID
FLTAPI disconnectCallback(_In_opt_ PVOID connection_cookie)
{
    UNREFERENCED_PARAMETER(connection_cookie);

    PAGED_CODE();

    KdPrint(("disconnectCallback() called\n"));

    FltCloseClientPort(fb_props.filter,
                       &fb_props.client_port);
}

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
#ifdef USE_FLT_INSTEAD_ZW
    { FLT_SECTION_CONTEXT,
      0,
      NULL,
      FLT_VARIABLE_SIZED_CONTEXTS,
      POOL_TAG,
      NULL,
      NULL,
      NULL},
#endif

    { FLT_CONTEXT_END }
};

static CONST FLT_REGISTRATION filter_registration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    contexts,
    callbacks,
    filterUnloadCallback,
    instanceSetupCallback,
#ifndef DISABLE_MANUAL_DETACH
    instanceQueryTeardownCallback,
#else
    NULL,
#endif
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

_Use_decl_annotations_
NTSTATUS driverEntry(_In_ PDRIVER_OBJECT driver_object,
                     _In_ PUNICODE_STRING registry_key_path)
{
    driver_object->DriverUnload = driverUnload;

    if (not checkOsVersion())
    {
        KdPrint(("Failed to check OS version\n"));
        return STATUS_NOT_SUPPORTED;
    }

    fb_props.thread = KeGetCurrentThread();

    fb_props.mutex = ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                     sizeof(FAST_MUTEX),
                                     POOL_TAG);
    if (not fb_props.mutex)
    {
        KdPrint(("Failed to allocate memory\n"));
        return STATUS_NO_MEMORY;
    }

    ExInitializeFastMutex(fb_props.mutex);

    if (not initializeFileBlocker(driver_object, registry_key_path))
    {
        KdPrint(("Initialization failed\n"));

        ExFreePool(fb_props.mutex);
        
        return STATUS_DEVICE_CONFIGURATION_ERROR;
    }

    NTSTATUS status = FltRegisterFilter(driver_object,
                                        &filter_registration,
                                        &fb_props.filter);
    if (not NT_SUCCESS(status))
    {
        KdPrint(("Failed to register filter\n"));

        ExFreePool(fb_props.mutex);
        uninitializeFileBlocker();

        return status;
    }

    KdPrint(("Filter registered\n"));

    PSECURITY_DESCRIPTOR security_descriptor;
    status = FltBuildDefaultSecurityDescriptor(&security_descriptor, FLT_PORT_ALL_ACCESS);
    if (not NT_SUCCESS(status))
    {
        KdPrint(("Failed to build security descriptor\n"));

        FltUnregisterFilter(fb_props.filter);
        ExFreePool(fb_props.mutex);
        uninitializeFileBlocker();

        return status;
    }

    OBJECT_ATTRIBUTES object_attributes;
    InitializeObjectAttributes(&object_attributes,
                               &SERVER_PORT_NAME,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL,
                               security_descriptor);

    status = FltCreateCommunicationPort(fb_props.filter,
                                        &fb_props.server_port,
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

        FltUnregisterFilter(fb_props.filter);
        ExFreePool(fb_props.mutex);
        uninitializeFileBlocker();

        return status;
    }

    status = FltStartFiltering(fb_props.filter);
    if (not NT_SUCCESS(status))
    {
        KdPrint(("Failed to start filtering\n"));

        FltUnregisterFilter(fb_props.filter);
        ExFreePool(fb_props.mutex);
        uninitializeFileBlocker();

        return status;
    }

    KdPrint(("Filtering started\n" \
             "Driver loaded\n"));
    return status;
}

_Use_decl_annotations_
VOID driverUnload(_In_ PDRIVER_OBJECT driver_object)
{
    UNREFERENCED_PARAMETER(driver_object);

    if (fb_props.server_port)
        FltCloseCommunicationPort(fb_props.server_port);

    if (fb_props.filter)
    {
        FltUnregisterFilter(fb_props.filter);

        KdPrint(("Filter unregistered\n"));
    }

    if (fb_props.mutex)
        ExFreePool(fb_props.mutex);

    uninitializeFileBlocker();

    KdPrint(("Driver unloaded\n"));
}

_Use_decl_annotations_
static NTSTATUS
FLTAPI filterUnloadCallback(_In_ FLT_FILTER_UNLOAD_FLAGS unload_flags)
{
    UNREFERENCED_PARAMETER(unload_flags);

    PAGED_CODE();

    KdPrint(("Filter unloaded\n"));
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
static NTSTATUS
FLTAPI instanceSetupCallback(_In_ PCFLT_RELATED_OBJECTS related_objects,
                             _In_ FLT_INSTANCE_SETUP_FLAGS setup_flags,
                             _In_ DEVICE_TYPE device_type,
                             _In_ FLT_FILESYSTEM_TYPE filesystem_type)
{
#ifdef NDEBUG
    UNREFERENCED_PARAMETER(setup_flags);
#endif

    PAGED_CODE();

    if (not related_objects)
        return STATUS_FLT_DO_NOT_ATTACH;

    FLT_ASSERT(fb_props.filter == related_objects->Filter);

    if ((ULONG_PTR)fb_props.thread != ExGetCurrentResourceThread())
        KdPrint(("WARNING: Multithreading detected!\n" \
                 "Main thread ID: %llu\n" \
                 "This thread ID: %llu\n",
                 (ULONG_PTR)fb_props.thread,
                 ExGetCurrentResourceThread()));

    KdPrint(("Setup flags: 0x%08X\n", setup_flags));
#ifndef NDEBUG
    printVolumeName(related_objects->Volume);
#endif

    if (device_type not_eq FILE_DEVICE_DISK_FILE_SYSTEM or
        (filesystem_type not_eq FLT_FSTYPE_NTFS and
         filesystem_type not_eq FLT_FSTYPE_FAT))
    {
        KdPrint(("Filter not loaded (device/filesystem types): %lu/%i\n",
                 device_type, filesystem_type));
        return STATUS_FLT_DO_NOT_ATTACH;
    }

    KdPrint(("Filter instance: %p\n", related_objects->Instance));

    ExAcquireFastMutex(fb_props.mutex);

    FLT_ASSERT(fb_props.num_flt_instances < MAX_FLT_INSTANCES);

    USHORT index = 0;
    for (; index < fb_props.num_flt_instances; ++index)
        if (fb_props.flt_instances[index] == related_objects->Instance)
            break;

    if (index == fb_props.num_flt_instances)
        fb_props.flt_instances[fb_props.num_flt_instances++] = related_objects->Instance;
    else
        KdPrint(("WARNING: The instance already exist!\n"));
    
    ExReleaseFastMutex(fb_props.mutex);

#ifdef USE_FLT_INSTEAD_ZW
    NTSTATUS status = FltRegisterForDataScan(related_objects->Instance);
    if (not NT_SUCCESS(status))
    {
        KdPrint(("Failed to register for data scan: 0x%08X\n", status));
     /* If FltRegisterForDataScan returns STATUS_NOT_SUPPORTED, a
        minifilter can still create sections for data scanning by
        calling FsRtlCreateSectionForDataScan. */
        return STATUS_FLT_DO_NOT_ATTACH;
    }
#endif

    KdPrint(("Filter loaded (device/filesystem types): %lu/%i\n",
             device_type, filesystem_type));
    return STATUS_SUCCESS;
}

#ifndef DISABLE_MANUAL_DETACH
_Use_decl_annotations_
static NTSTATUS
FLTAPI instanceQueryTeardownCallback(_In_ PCFLT_RELATED_OBJECTS related_objects,
                                     _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS teardown_flags)
{
    // No flags are currently defined.
    // 02/22/2024, learn.microsoft.com
    UNREFERENCED_PARAMETER(teardown_flags);

    PAGED_CODE();

    if (not related_objects)
        return STATUS_FLT_DO_NOT_DETACH;

    FLT_ASSERT(fb_props.filter == related_objects->Filter);

    if ((ULONG_PTR)fb_props.thread != ExGetCurrentResourceThread())
        KdPrint(("WARNING: Multithreading detected!\n" \
                 "Main thread ID: %llu\n" \
                 "This thread ID: %llu\n",
                 (ULONG_PTR)fb_props.thread,
                 ExGetCurrentResourceThread()));

    KdPrint(("Filter instance: %p\n", related_objects->Instance));
    
    ExAcquireFastMutex(fb_props.mutex);

    FLT_ASSERT(fb_props.num_flt_instances > 0);

    USHORT index = 0;
    for (; index < fb_props.num_flt_instances; ++index)
        if (fb_props.flt_instances[index] == related_objects->Instance)
            break;

    if (index == fb_props.num_flt_instances)
        KdPrint(("WARNING: The instance does not exist!\n"));
    else
    {
        for (; index < fb_props.num_flt_instances - 1; ++index)
            fb_props.flt_instances[index] = fb_props.flt_instances[index + 1];

        fb_props.flt_instances[--fb_props.num_flt_instances] = NULL;
    }
    
    ExReleaseFastMutex(fb_props.mutex);

    return STATUS_SUCCESS;
}
#endif

_Use_decl_annotations_
static FLT_PREOP_CALLBACK_STATUS
FLTAPI preOperationCallback(_Inout_ PFLT_CALLBACK_DATA callback_data,
                            _In_ PCFLT_RELATED_OBJECTS related_objects,
                            _Outptr_result_maybenull_ PVOID* completion_context)
{
    PAGED_CODE();

    if (completion_context)
        *completion_context = NULL;

    if (not callback_data or
        not related_objects
#ifdef PARANOID_MODE
        or not callback_data->Iopb
        or not callback_data->Iopb->TargetFileObject
        or not related_objects->Filter
        or not related_objects->Instance
#endif
        )
    {
        KdPrint(("WARNING: Null pointer catched!\n"));
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (not FLT_IS_IRP_OPERATION(callback_data))
    {
        KdPrint(("WARNING: This is not IRP operation!\n"));
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (callback_data->RequestorMode == KernelMode)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    PFLT_IO_PARAMETER_BLOCK io_parameter_block = callback_data->Iopb;

    // Удаление файла в корзину (второй этап, поздно блокировать)
    // Эта проверка дублируется без использования FILE_OBJECT
    if (io_parameter_block->TargetFileObject->DeletePending)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

#ifdef NEW_FEATURES_TESTING
    // НЕ файл
    // Эта проверка дублируется отдельно IRP_MJ_CREATE без использования FILE_OBJECT
    // и для IRP_MJ_SET_INFORMATION с использованием предварительно открытого (!) FILE_OBJECT
    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_file_object
    if (io_parameter_block->TargetFileObject->Type != 5)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
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

            KdPrint(("This is rename or move operation\n"));
        }

        BOOLEAN is_directory = FALSE;
        // WARNING: This routine can only be called on an opened file object!
        NTSTATUS status = FltIsDirectory(io_parameter_block->TargetFileObject,
                                         related_objects->Instance,
                                         &is_directory);
        if (not NT_SUCCESS(status))
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

#ifdef NEW_FEATURES_TESTING
        if ((create_options & (FILE_SYNCHRONOUS_IO_ALERT |       // все операции с файлом
                               FILE_SYNCHRONOUS_IO_NONALERT)) or // выполняются синхронно
            (create_options & FILE_WRITE_THROUGH) or             // сквозная запись файлов (lazy-write off)
            (create_options & FILE_DELETE_ON_CLOSE))             // про удаление (не в корзину) и временные файлы
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
#endif

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
             callback_data->Iopb->MajorFunction));

    if (callback_data->Iopb->TargetFileObject)
        KdPrint(("[FLT_CALLBACK_DATA] FileName: %wZ\n",
                 &callback_data->Iopb->TargetFileObject->FileName));
    if (related_objects->FileObject)
        KdPrint(("[FLT_RELATED_OBJECTS] FileName: %wZ\n",
                 &related_objects->FileObject->FileName));

    FLT_ASSERTMSG("OBJECTS MISMATCH", callback_data->Iopb->TargetFileObject ==
                                      related_objects->FileObject);
    
    if (callback_data->Iopb->MajorFunction == IRP_MJ_CREATE)
    {
        // The high 8 bits contains the CreateDisposition values.
        KdPrint(("[IRP_MJ_CREATE] CreateDisposition: 0x%08X\n",
                 callback_data->Iopb->Parameters.Create.Options >> 24));
        // The low 24 bits contains CreateOptions flag values.
        KdPrint(("[IRP_MJ_CREATE] CreateOptions: 0x%08X\n",
                 callback_data->Iopb->Parameters.Create.Options & 0x00FFFFFF));
    }
    else
    if (callback_data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION)
    {
        KdPrint(("[IRP_MJ_SET_INFORMATION] FileInformationClass: %i\n",
                 callback_data->Iopb->Parameters.SetFileInformation.FileInformationClass));
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
    NTSTATUS status = FltGetFileNameInformation(callback_data,
                                                FLT_FILE_NAME_NORMALIZED,
                                                &file_name_info);
    if (not NT_SUCCESS(status))
    {
        KdPrint(("Failed to get file name info: 0x%08X\n", status));
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

#ifdef USE_FLT_INSTEAD_ZW
    if ((io_parameter_block->MajorFunction == IRP_MJ_SET_INFORMATION &&
         isTextBlocked2(related_objects->Filter,
                        related_objects->Instance,
                        io_parameter_block->TargetFileObject)
        ) ||
        (io_parameter_block->MajorFunction == IRP_MJ_CREATE &&
         isTextBlocked(related_objects->Filter,
                       related_objects->Instance,
#ifndef NDEBUG
                       io_parameter_block->TargetFileObject,
#endif
                       file_name_info->Name)))
#else
    if (isTextBlocked(file_name_info->Name))
#endif
    {
        KdPrint(("Blocking operation on file: %wZ\n", &file_name_info->Name));

        FltReleaseFileNameInformation(file_name_info);
                
        callback_data->IoStatus.Status = STATUS_ACCESS_DENIED;
        callback_data->IoStatus.Information = 0;

        return FLT_PREOP_COMPLETE;
    }

    KdPrint(("This content is not blocked\n"));

    FltReleaseFileNameInformation(file_name_info);

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
