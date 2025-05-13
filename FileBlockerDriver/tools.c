// Порядок подключения заголовочных файлов важен!
#ifdef USE_FLT_INSTEAD_ZW
// Подгружает ntifs.h
#include <fltKernel.h>
#else
#if !defined(USE_DEFAULT_CONFIG_PATH) && defined(USE_FULL_CONFIG_PATH)
#include <ntifs.h>
#endif // !USE_DEFAULT_CONFIG_PATH && USE_FULL_CONFIG_PATH
#endif // USE_FLT_INSTEAD_ZW
#include <ntddk.h>
#include <ntstrsafe.h>

#include <iso646.h>

#include "tools.h"

#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))

#define POOL_TAG '1gaT'

#define MAX_PATH_LEN    256U
// Один байт зарезервирован!
#define MAX_FILE_LEN   1024U
#define MAX_STRING_LEN  256U

static CONST UNICODE_STRING RECYCLE_BIN_NAME  = RTL_CONSTANT_STRING(L"$RECYCLE.BIN");

#ifndef USE_DEFAULT_CONFIG_PATH
static       UNICODE_STRING VALUE_ENTRY_NAME  = RTL_CONSTANT_STRING(L"ConfigFile");
#else
static       UNICODE_STRING CONFIG_FILE_PATH  = RTL_CONSTANT_STRING(L"\\??\\C:\\config.ini");
#endif

typedef struct _FILE_BLOCKER_CONFIGURATION
{
    UNICODE_STRING ext_to_block;
    UNICODE_STRING text_to_block;
} FILE_BLOCKER_CONFIGURATION, *PFILE_BLOCKER_CONFIGURATION;

static FILE_BLOCKER_CONFIGURATION fb_config;

typedef struct _CONFIGURATION_PARAMETER
{
    ANSI_STRING name;
    UTF8_STRING def_value;
    PUNICODE_STRING value;
} CONFIGURATION_PARAMETER;

static CONFIGURATION_PARAMETER fb_config_params[] = {
    { RTL_CONSTANT_STRING("ext_to_block"),
      RTL_CONSTANT_STRING(".txt"),
      &fb_config.ext_to_block },

    { RTL_CONSTANT_STRING("text_to_block"),
      RTL_CONSTANT_STRING("This текст should be blocked!"),
      &fb_config.text_to_block }
};

static CONST USHORT num_fb_config_params = sizeof(fb_config_params) / sizeof(fb_config_params[0]);

static PUNICODE_STRING getValueReferenceByName(_In_reads_bytes_(length) PCCH string,
                                               _In_ ULONG length)
{
    if (length == 0 || length > MAX_STRING_LEN)
    {
        KdPrint(("Invalid parameter name\n"));
        return NULL;
    }

    CONST ANSI_STRING name = {
        .Buffer = (PCHAR)string,
        .Length = (USHORT)length,
        .MaximumLength = (USHORT)length
    };

    for (USHORT index = 0; index < num_fb_config_params; ++index)
    {
        if (RtlEqualString(&fb_config_params[index].name, &name, TRUE))
        {
            KdPrint(("Parameter name: \"%Z\"\n", &name));
            return fb_config_params[index].value;
        }
    }

    KdPrint(("Parameter not found\n"));
    return NULL;
}

static BOOLEAN setValueByReference(_In_ PUNICODE_STRING value_reference,
                                   _In_reads_bytes_(length) PCCH string,
                                   _In_ ULONG length)
{
    static CHAR buffer[MAX_STRING_LEN * sizeof(WCHAR)];
#ifdef PARANOID_MODE
    if (not value_reference or
        not string)
        return FALSE;
#endif
    if (length == 0 || length > sizeof(buffer))
    {
        KdPrint(("Invalid parameter value\n"));
        return FALSE;
    }

    NTSTATUS status = RtlUTF8ToUnicodeN((PWCHAR)buffer,
                                        sizeof(buffer),
                                        &length,
                                        string,
                                        length);
    if (not NT_SUCCESS(status))
    {
        KdPrint(("Failed to convert string: 0x%08X\n", status));
        return FALSE;
    }

    CONST UNICODE_STRING value = {
        .Buffer = (PWCHAR)buffer,
        .Length = (USHORT)length,
        .MaximumLength = (USHORT)length
    };

    status = RtlUnicodeStringCopy(value_reference, &value);
    if (not NT_SUCCESS(status))
    {
        KdPrint(("Failed to copy string: 0x%08X\n", status));
        return FALSE;
    }
        
    KdPrint(("Parameter value: \"%wZ\"\n", &value));
    return TRUE;
}

static NTSTATUS allocUnicodeString(_Inout_ PUNICODE_STRING unicode_string)
{
    if (not unicode_string)
        return STATUS_INVALID_PARAMETER;

    if (unicode_string->Buffer)
    {
        KdPrint(("WARNING: String not empty!\n"));

        ExFreePool(unicode_string->Buffer);
    }

    unicode_string->Length = 0;
    unicode_string->MaximumLength = MAX_STRING_LEN * sizeof(WCHAR);
    unicode_string->Buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                             unicode_string->MaximumLength,
                                             POOL_TAG);
    if (not unicode_string->Buffer)
    {
        KdPrint(("Failed to allocate memory\n"));

        unicode_string->MaximumLength = 0;
        
        return STATUS_NO_MEMORY;
    }

    RtlZeroMemory(unicode_string->Buffer, unicode_string->MaximumLength);

    return STATUS_SUCCESS;
}

static VOID freeUnicodeString(_Inout_ PUNICODE_STRING unicode_string)
{
    if (not unicode_string)
        return;

    unicode_string->Length = 0;
    unicode_string->MaximumLength = 0;

    if (unicode_string->Buffer)
    {
        ExFreePool(unicode_string->Buffer);
        unicode_string->Buffer = NULL;
    }
}

static BOOLEAN initDefaultConfig()
{
    LONG index = 0;
    NTSTATUS status = STATUS_SUCCESS;
    while (index < num_fb_config_params)
    {
        status = allocUnicodeString(fb_config_params[index].value);
        if (not NT_SUCCESS(status))
            break;

        status = RtlUTF8StringToUnicodeString(fb_config_params[index].value,
                                              &fb_config_params[index].def_value,
                                              FALSE);
        if (not NT_SUCCESS(status))
        {
            KdPrint(("Failed to convert string: 0x%08X\n", status));

            freeUnicodeString(fb_config_params[index].value);

            break;
        }

        ++index;
    }

    if (not NT_SUCCESS(status))
    {
        while (--index >= 0)
            freeUnicodeString(fb_config_params[index].value);

        return FALSE;
    }

    return TRUE;
}

#ifdef UNDER_CONSTRUCTION
_Success_(return != FALSE)
static BOOLEAN getLogFilePath(_Out_ PUNICODE_STRING log_file_path)
{
    static CHAR buffer[(MAX_PATH_LEN + 1) * sizeof(WCHAR)];
    static CONST USHORT length = sizeof(buffer);
#ifdef PARANOID_MODE
    if (not log_file_path)
        return FALSE;
#endif
    // Можно и не чистить память.
    RtlZeroMemory(buffer, length);

    UNICODE_STRING unicode_string = {
        .Buffer = (PWCHAR)buffer,
        .Length = 0,
        .MaximumLength = length
    };

    RTL_QUERY_REGISTRY_TABLE query_table[] = {
        { NULL,
          RTL_QUERY_REGISTRY_REQUIRED | RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_TYPECHECK
       /* Kernel-mode drivers must specify the RTL_QUERY_REGISTRY_NOEXPAND flag to prevent
          calling environment variable routines. These routines are unsafe, so kernel-mode
          drivers should not use them. */
          | RTL_QUERY_REGISTRY_NOEXPAND,
          L"LogFile",
          &unicode_string,
          (REG_EXPAND_SZ << RTL_QUERY_REGISTRY_TYPECHECK_SHIFT) | REG_NONE,
          NULL,
          0 },

        { NULL,
          0,
          NULL }
    };

    NTSTATUS status = RtlQueryRegistryValues(RTL_REGISTRY_SERVICES,
                                             L"FileBlockerDriver",
                                             query_table,
                                             NULL,
                                             NULL);
    if (not NT_SUCCESS(status))
    {
        KdPrint(("Failed to query registry values: 0x%08X\n", status));
        return FALSE;
    }

    size_t num_bytes;
    status = RtlUnalignedStringCbLengthW(unicode_string.Buffer,
                                         unicode_string.MaximumLength,
                                         &num_bytes);
    if (not NT_SUCCESS(status))
    {
        KdPrint(("Failed to determine string length: 0x%08X\n", status));
        return FALSE;
    }

    NT_VERIFY(unicode_string.Length == (USHORT)num_bytes);

    KdPrint(("Log file path: \"%wZ\"\n", &unicode_string));

    *log_file_path = unicode_string;

    return TRUE;
}
#endif

#ifndef USE_DEFAULT_CONFIG_PATH
_Success_(return != FALSE)
static BOOLEAN getConfigFileName(_In_ PUNICODE_STRING registry_key_path,
                                 _Out_ PUNICODE_STRING config_file_name)
{
    static CHAR buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) +
                       (MAX_PATH_LEN + 1) * sizeof(WCHAR)];
#ifdef PARANOID_MODE
    if (not registry_key_path or
        not config_file_name)
        return FALSE;
#endif
    OBJECT_ATTRIBUTES object_attributes;
    InitializeObjectAttributes(&object_attributes,
                               registry_key_path,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    HANDLE key_handle;
    NTSTATUS status = ZwOpenKey(&key_handle, KEY_QUERY_VALUE, &object_attributes);
    if (not NT_SUCCESS(status))
    {
        KdPrint(("Failed to open registry key: 0x%08X\n", status));
        return FALSE;
    }

    ULONG length = sizeof(buffer);
    // Можно и не чистить память.
    RtlZeroMemory(buffer, length);
    status = ZwQueryValueKey(key_handle,
                             &VALUE_ENTRY_NAME,
                             KeyValuePartialInformation,
                             buffer,
                             length,
                             &length);

    ZwClose(key_handle);

    if (not NT_SUCCESS(status))
    {
        KdPrint(("Failed to query value entry: 0x%08X\n", status));
        return FALSE;
    }

    PKEY_VALUE_PARTIAL_INFORMATION value_info = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;
    if (value_info->Type != REG_SZ)
    {
        KdPrint(("Wrong value entry type\n"));
        return FALSE;
    }

    if (value_info->DataLength <= sizeof(WCHAR) or
        *((PWCHAR)(value_info->Data + value_info->DataLength) - 1) != L'\0')
    {
        KdPrint(("Wrong value entry\n"));
        return FALSE;
    }

    config_file_name->Buffer = (PWCHAR)value_info->Data;
    config_file_name->Length = (USHORT)(value_info->DataLength - sizeof(WCHAR));
    config_file_name->MaximumLength = config_file_name->Length;

    KdPrint(("Config file name: \"%wZ\"\n", config_file_name));
    return TRUE;
}

#ifdef USE_FULL_CONFIG_PATH
_Success_(return != FALSE)
static BOOLEAN getConfigFilePath(_In_ HANDLE root_directory_handle,
                                 _In_ PCUNICODE_STRING config_file_name,
                                 _Out_ PUNICODE_STRING config_file_path)
{
    static CHAR buffer[sizeof(OBJECT_NAME_INFORMATION) +
                       (MAX_PATH_LEN + 1) * sizeof(WCHAR)];
#ifdef PARANOID_MODE
    if (not config_file_name or
        not config_file_path)
        return FALSE;
#endif
    PFILE_OBJECT root_directory_object;
    NTSTATUS status = ObReferenceObjectByHandle(root_directory_handle,
                                                GENERIC_READ,
                                                *IoFileObjectType,
                                                KernelMode,
                                                &root_directory_object,
                                                NULL);
    if (not NT_SUCCESS(status))
    {
        KdPrint(("Failed to get directory object: 0x%08X\n", status));
        return FALSE;
    }

    KdPrint(("Root directory name: \"%wZ\"\n", &root_directory_object->FileName));

    ULONG length = sizeof(buffer);
    // Можно и не чистить память.
    RtlZeroMemory(buffer, length);
    status = ObQueryNameString(root_directory_object->DeviceObject,
                               (POBJECT_NAME_INFORMATION)buffer,
                               length,
                               &length);
    if (not NT_SUCCESS(status))
    {
        KdPrint(("Failed to query device name: 0x%08X\n", status));

        ObDereferenceObject(root_directory_object);

        return FALSE;
    }

    POBJECT_NAME_INFORMATION object_name_info = (POBJECT_NAME_INFORMATION)buffer;
    object_name_info->Name.MaximumLength = (USHORT)(sizeof(buffer) - sizeof(OBJECT_NAME_INFORMATION));

    NT_ASSERTMSG("INVALID POINTER", object_name_info->Name.Buffer ==
                                    (PWCHAR)(buffer + sizeof(OBJECT_NAME_INFORMATION)));

    NT_ASSERTMSG("INVALID SIZE",    object_name_info->Name.MaximumLength ==
                                    (USHORT)((buffer + sizeof(buffer)) - (PCHAR)object_name_info->Name.Buffer));

    size_t num_bytes;
    status = RtlUnalignedStringCbLengthW(object_name_info->Name.Buffer,
                                         object_name_info->Name.MaximumLength,
                                         &num_bytes);
    if (not NT_SUCCESS(status))
    {
        KdPrint(("Failed to determine string length: 0x%08X\n", status));

        ObDereferenceObject(root_directory_object);

        return FALSE;
    }

    NT_VERIFY(object_name_info->Name.Length == (USHORT)num_bytes);

    KdPrint(("Device name: \"%wZ\"\n", &object_name_info->Name));

    // Возможно в FILE_OBJECT имя составное и начало имени в поле RelatedFileObject->FileName.
    if (not NT_SUCCESS(status = RtlUnicodeStringCat(&object_name_info->Name, &root_directory_object->FileName)) or
        not NT_SUCCESS(status = RtlUnicodeStringCatString(&object_name_info->Name, L"\\")) or
        not NT_SUCCESS(status = RtlUnicodeStringCat(&object_name_info->Name, config_file_name)))
    {
        KdPrint(("Failed to concatenate strings: 0x%08X\n", status));

        ObDereferenceObject(root_directory_object);

        return FALSE;
    }

    ObDereferenceObject(root_directory_object);

    KdPrint(("Config file path: \"%wZ\"\n", &object_name_info->Name));

    *config_file_path = object_name_info->Name;

    return TRUE;
}
#endif // USE_FULL_CONFIG_PATH
#endif // !USE_DEFAULT_CONFIG_PATH

static VOID prepareConfigData(_Inout_updates_bytes_to_(_Old_(*size), *size) PCH data,
                              _Inout_ PULONG size)
{
    if (data == NULL ||
        size == NULL ||
        *size == 0)
        return;

    ULONG j = 0;
    for (ULONG i = 0; i < *size; ++i)
    {
        if (data[i] == '\r')
            continue;

        data[j++] = data[i];
    }

    *size = j;
}

static VOID parseConfigData(_In_reads_bytes_(size) PCCH data,
                            _In_ ULONG size)
{
    if (data == NULL ||
        size == 0)
        return;

    BOOLEAN is_name = TRUE;
    PUNICODE_STRING value_reference = NULL;
    for (ULONG i = 0, j = 0; i < size; ++i)
    {
        if (is_name && data[i] == '=')
        {
            value_reference = getValueReferenceByName(data + j, i - j);
            if (value_reference != NULL)
            {
                is_name = FALSE;
            }
            else
            {
                // до конца текущей строки
                do {
                    ++i;
                }
                while (i < size && data[i] != '\n');

                // до начала следующей непустой строки
                while ((i + 1) < size && data[i + 1] == '\n')
                {
                    ++i;
                }
            }

            j = i + 1;
        }
        else if (!is_name && data[i] == '\n')
        {
            setValueByReference(value_reference, data + j, i - j);
            value_reference = NULL;
            is_name = TRUE;

            // до начала следующей непустой строки
            while ((i + 1) < size && data[i + 1] == '\n')
            {
                ++i;
            }

            j = i + 1;
        }
    }
}

_Success_(return != FALSE)
static BOOLEAN openConfigFile(_In_opt_ HANDLE root_directory_handle,
                              _In_ PUNICODE_STRING config_file_name,
                              _Out_ PHANDLE config_file_handle)
{
#ifdef PARANOID_MODE
    if (not config_file_name or
        not config_file_handle)
        return FALSE;
#endif
    OBJECT_ATTRIBUTES object_attributes;
    InitializeObjectAttributes(&object_attributes,
                               config_file_name,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               root_directory_handle,
                               NULL);

    IO_STATUS_BLOCK io_status_block;
    NTSTATUS status = ZwOpenFile(config_file_handle,
                                 FILE_READ_DATA,
                                 &object_attributes,
                                 &io_status_block,
                                 FILE_SHARE_READ,
                                 FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
    if (not NT_SUCCESS(status))
    {
        KdPrint(("Failed to open file: 0x%08X\n", status));
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN checkConfigFile(_In_ HANDLE config_file_handle)
{
    IO_STATUS_BLOCK io_status_block;
    FILE_STANDARD_INFORMATION file_standard_info;
    NTSTATUS status = ZwQueryInformationFile(config_file_handle,
                                             &io_status_block,
                                             &file_standard_info,
                                             sizeof(file_standard_info),
                                             FileStandardInformation);
    if (not NT_SUCCESS(status))
    {
        KdPrint(("Failed to get file info: 0x%08X\n", status));
        return FALSE;
    }

    if (file_standard_info.EndOfFile.QuadPart == 0)
    {
        KdPrint(("Empty file\n"));
        return FALSE;
    }

    if (file_standard_info.EndOfFile.QuadPart > MAX_FILE_LEN)
    {
        KdPrint(("File to big\n"));
        return FALSE;
    }

    return TRUE;
}

_Success_(return != FALSE)
static BOOLEAN readConfigFile(_In_ HANDLE config_file_handle,
                              _Out_writes_bytes_(*length) PCHAR buffer,
                              _Inout_ PULONG length)
{
    IO_STATUS_BLOCK io_status_block;
    LARGE_INTEGER offset = {
        .QuadPart = 0
    };
    NTSTATUS status = ZwReadFile(config_file_handle,
                                 NULL,
                                 NULL,
                                 NULL,
                                 &io_status_block,
                                 buffer,
                                 *length,
                                 &offset,
                                 NULL);
    if (not NT_SUCCESS(status))
    {
        KdPrint(("Failed to read file: 0x%08X\n", status));
        return FALSE;
    }

    *length = (ULONG)io_status_block.Information;

    return TRUE;
}

_Use_decl_annotations_
BOOLEAN initializeFileBlocker(_In_ PDRIVER_OBJECT driver_object,
                              _In_ PUNICODE_STRING registry_key_path)
{
#ifdef USE_DEFAULT_CONFIG_PATH
    UNREFERENCED_PARAMETER(driver_object);
    UNREFERENCED_PARAMETER(registry_key_path);
#else
    if (not driver_object or
        not registry_key_path)
        return FALSE;
#endif

    BOOLEAN result = initDefaultConfig();
    if (not result)
        return FALSE;

#ifdef UNDER_CONSTRUCTION
    // Замысел этой функции был в расширении
    // переменной окружения %SystemRoot%, но
    // я не знаю как обойти запрет на это.
    UNICODE_STRING log_file_path;
    if (not getLogFilePath(&log_file_path))
        goto End;
#endif

#ifndef USE_DEFAULT_CONFIG_PATH
    HANDLE root_directory_handle;
    NTSTATUS status = IoGetDriverDirectory(driver_object,
                                           DriverDirectoryImage,
                                           0,
                                           &root_directory_handle);
    if (not NT_SUCCESS(status))
    {
        KdPrint(("Failed to get driver directory: 0x%08X\n", status));
        goto End;
    }

    UNICODE_STRING config_file_name;
    if (not getConfigFileName(registry_key_path, &config_file_name))
    {
        ZwClose(root_directory_handle);

        goto End;
    }

#ifdef USE_FULL_CONFIG_PATH
    UNICODE_STRING config_file_path;
    result = getConfigFilePath(root_directory_handle,
                               &config_file_name,
                               &config_file_path);

    ZwClose(root_directory_handle);

    if (not result)
        goto End;
    
#endif // USE_FULL_CONFIG_PATH
#else
    KdPrint(("Config file path: %wZ\n", &CONFIG_FILE_PATH));
#endif // !USE_DEFAULT_CONFIG_PATH

    HANDLE config_file_handle;
    result = openConfigFile(
#if !defined(USE_DEFAULT_CONFIG_PATH) && !defined(USE_FULL_CONFIG_PATH)
                            root_directory_handle,
#else
                            NULL,
#endif
#if defined(USE_DEFAULT_CONFIG_PATH)
                            &CONFIG_FILE_PATH,
#elif defined(USE_FULL_CONFIG_PATH)
                            &config_file_path,
#else
                            &config_file_name,
#endif
                            &config_file_handle);

#if !defined(USE_DEFAULT_CONFIG_PATH) && !defined(USE_FULL_CONFIG_PATH)
    ZwClose(root_directory_handle);
#endif

    if (not result)
        goto End;

    if (not checkConfigFile(config_file_handle))
    {
        ZwClose(config_file_handle);

        goto End;
    }

    PCHAR buffer = MmAllocateNonCachedMemory(MAX_FILE_LEN);
    if (not buffer)
    {
        KdPrint(("Failed to allocate memory\n"));

        ZwClose(config_file_handle);

        goto End;
    }

    ULONG length = MAX_FILE_LEN - 1;
    result = readConfigFile(config_file_handle,
                            buffer,
                            &length);

    ZwClose(config_file_handle);

    if (result)
    {
        KdPrint(("Number of bytes read: %lu\n", length));

        buffer[length++] = '\n';
        prepareConfigData(buffer, &length);
        parseConfigData(buffer, length);

        MmFreeNonCachedMemory(buffer, MAX_FILE_LEN);

        return TRUE;
    }

    MmFreeNonCachedMemory(buffer, MAX_FILE_LEN);

End:
    uninitializeFileBlocker();

    return FALSE;
}

VOID uninitializeFileBlocker()
{
    for (USHORT index = 0; index < num_fb_config_params; ++index)
        freeUnicodeString(fb_config_params[index].value);
}

_Use_decl_annotations_
BOOLEAN isRecycleBinPath(_In_reads_bytes_(file_name_len) PWCH file_name,
                         _In_ ULONG file_name_len)
{
    if (file_name == NULL ||
        file_name_len < RECYCLE_BIN_NAME.Length)
        return FALSE;

    PWCH dollar_sign_pos = NULL;
    for (ULONG i = 0; i < file_name_len / sizeof(WCHAR); ++i)
        if (file_name[i] == L'$')
        {
            dollar_sign_pos = file_name + i;
            break;
        }

    if (dollar_sign_pos != NULL)
    {
        CONST USHORT crop_file_name_len = (USHORT)(file_name_len - (dollar_sign_pos - file_name) * sizeof(WCHAR));
        CONST UNICODE_STRING crop_file_name = {
            .Buffer = dollar_sign_pos,
            .Length = crop_file_name_len,
            .MaximumLength = crop_file_name_len
        };

        return RtlPrefixUnicodeString(&RECYCLE_BIN_NAME, &crop_file_name, TRUE);
    }

    return FALSE;
}

_Use_decl_annotations_
BOOLEAN isExtensionBlocked(_In_ PCUNICODE_STRING file_name)
{
    if (file_name == NULL ||
        file_name->Buffer == NULL ||
        file_name->Length < fb_config.ext_to_block.Length)
        return FALSE;

    PWCH dot_pos = NULL;
    for (SHORT i = file_name->Length / sizeof(WCHAR) - 1; i >= 0; --i)
        if (file_name->Buffer[i] == L'.')
        {
            dot_pos = file_name->Buffer + i;
            break;
        }

    if (dot_pos != NULL)
    {
        CONST USHORT file_ext_len = (USHORT)(file_name->Length - (dot_pos - file_name->Buffer) * sizeof(WCHAR));
        CONST UNICODE_STRING file_ext = {
            .Buffer = dot_pos,
            .Length = file_ext_len,
            .MaximumLength = file_ext_len
        };

        return RtlEqualUnicodeString(&file_ext, &fb_config.ext_to_block, TRUE);
    }

    return FALSE;
}

#ifndef USE_FLT_INSTEAD_ZW
_Use_decl_annotations_
BOOLEAN isTextBlocked(_In_ UNICODE_STRING file_name)
{
    if (file_name.Buffer == NULL ||
        file_name.Length == 0)
        return FALSE;

    OBJECT_ATTRIBUTES object_attributes;
    InitializeObjectAttributes(&object_attributes,
                               &file_name,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    HANDLE file_handle;
    IO_STATUS_BLOCK io_status_block;
    NTSTATUS status = ZwCreateFile(&file_handle,
                                   FILE_GENERIC_READ,
                                   &object_attributes,
                                   &io_status_block,
                                   NULL,
                                   FILE_ATTRIBUTE_NORMAL,
                                   FILE_SHARE_READ | FILE_SHARE_DELETE,
                                   FILE_OPEN,
                                   FILE_NON_DIRECTORY_FILE,
                                   NULL,
                                   0);
    if (not NT_SUCCESS(status))
    {
        KdPrint(("Failed to open file: 0x%08X\n", status));
        return FALSE;
    }

    FILE_STANDARD_INFORMATION file_standard_info;
    status = ZwQueryInformationFile(file_handle,
                                    &io_status_block,
                                    &file_standard_info,
                                    sizeof(file_standard_info),
                                    FileStandardInformation);
    if (not NT_SUCCESS(status))
    {
        KdPrint(("Failed to get file info: 0x%08X\n", status));

        ZwClose(file_handle);

        return FALSE;
    }

    KdPrint(("File size: %lli/%lli bytes\n", file_standard_info.EndOfFile.QuadPart,
                                             file_standard_info.AllocationSize.QuadPart));

    if (file_standard_info.EndOfFile.QuadPart == 0)
    {
        KdPrint(("Empty file\n"));

        ZwClose(file_handle);

        return FALSE;
    }

    HANDLE section_handle;
    // ZwCreateSection rounds this value up
    // to the nearest multiple of PAGE_SIZE.
    LARGE_INTEGER max_section_size = {
        .QuadPart = MIN(file_standard_info.EndOfFile.QuadPart,
                        fb_config.text_to_block.Length)
    };
    status = ZwCreateSection(&section_handle,
                             SECTION_MAP_READ,
                             NULL,
                             &max_section_size,
                             PAGE_READONLY,
                             SEC_COMMIT,
                             file_handle);
    if (not NT_SUCCESS(status))
    {
        KdPrint(("Failed to create section: 0x%08X\n", status));

        ZwClose(file_handle);

        return FALSE;
    }

    PVOID base_address = NULL;
    SIZE_T view_size = 0;
    status = ZwMapViewOfSection(section_handle,
                                ZwCurrentProcess(),
                                &base_address,
                                0,
                                0,
                                NULL,
                                &view_size,
                                ViewUnmap,
                                0,
                                PAGE_READONLY);
    if (not NT_SUCCESS(status))
    {
        KdPrint(("Failed to map view: 0x%08X\n", status));

        ZwClose(section_handle);
        ZwClose(file_handle);

        return FALSE;
    }
    
    UTF8_STRING utf8_string = {
        .Buffer = (PCHAR)base_address,
        .Length = (USHORT)max_section_size.QuadPart,
        .MaximumLength = (USHORT)MIN(file_standard_info.EndOfFile.QuadPart,
                                     (LONGLONG)view_size)
    };

    NT_VERIFY(utf8_string.Length <= utf8_string.MaximumLength);

    KdPrint(("String size: %hu/%hu bytes\n", utf8_string.Length,          // нужно прочитать
                                             utf8_string.MaximumLength)); // можно прочитать

    UNICODE_STRING unicode_string;
    BOOLEAN should_block = FALSE;
    status = RtlUTF8StringToUnicodeString(&unicode_string, &utf8_string, TRUE);
    if (NT_SUCCESS(status))
    {
        should_block = RtlPrefixUnicodeString(&fb_config.text_to_block,
                                              &unicode_string,
                                              TRUE);

        RtlFreeUnicodeString(&unicode_string);
    }
    else
    {
        KdPrint(("Failed to convert string: 0x%08X\n", status));
    }

    ZwUnmapViewOfSection(ZwCurrentProcess(), base_address);
    ZwClose(section_handle);
    ZwClose(file_handle);

    return should_block;
}
#else
_Use_decl_annotations_
BOOLEAN isTextBlocked(_In_ PFLT_FILTER filter,
                      _In_ PFLT_INSTANCE instance,
#ifndef NDEBUG
                      _In_opt_ PFILE_OBJECT in_file_object,
#endif
                      _In_ UNICODE_STRING file_name)
{
#ifdef PARANOID_MODE
    if (not filter or
        not instance)
        return FALSE;
#endif
    if (file_name.Buffer == NULL ||
        file_name.Length == 0)
        return FALSE;

#ifndef NDEBUG
    if (in_file_object)
    {
        if (in_file_object->ReadAccess ||
            in_file_object->WriteAccess ||
            in_file_object->DeleteAccess)
            KdPrint(("WARNING: The file is already open!\n"));

        KdPrint(("[FILE_OBJECT] Flags: 0x%032X\n", in_file_object->Flags));
    }
#endif

    OBJECT_ATTRIBUTES object_attributes;
    InitializeObjectAttributes(&object_attributes,
                               &file_name,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    HANDLE file_handle;
    PFILE_OBJECT file_object;
    IO_STATUS_BLOCK io_status_block;
    NTSTATUS status = FltCreateFileEx(filter,
                                      instance,
                                      &file_handle,
                                      &file_object,
                                      FILE_GENERIC_READ,
                                      &object_attributes,
                                      &io_status_block,
                                      NULL,
                                      FILE_ATTRIBUTE_NORMAL,
                                      FILE_SHARE_READ | FILE_SHARE_DELETE,
                                      FILE_OPEN,
                                      FILE_NON_DIRECTORY_FILE,
                                      NULL,
                                      0,
                                      0);
    if (not NT_SUCCESS(status))
    {
        KdPrint(("Failed to open file: 0x%08X\n", status));
        return FALSE;
    }

    FILE_STANDARD_INFORMATION file_standard_info;
    // WARNING: This routine can only be called on an opened file object!
    status = FltQueryInformationFile(instance,
                                     file_object,
                                     &file_standard_info,
                                     sizeof(file_standard_info),
                                     FileStandardInformation,
                                     NULL);
    if (not NT_SUCCESS(status))
    {
        KdPrint(("Failed to get file info: 0x%08X\n", status));

        FltClose(file_handle);
        ObDereferenceObject(file_object);

        return FALSE;
    }

    KdPrint(("File size: %lli/%lli bytes\n", file_standard_info.EndOfFile.QuadPart,
                                             file_standard_info.AllocationSize.QuadPart));

    if (file_standard_info.EndOfFile.QuadPart == 0)
    {
        KdPrint(("Empty file\n"));

        FltClose(file_handle);
        ObDereferenceObject(file_object);

        return FALSE;
    }

    CONST BOOLEAN should_block = isTextBlocked2(filter,
                                                instance,
                                                file_object);
    
    FltClose(file_handle);
    ObDereferenceObject(file_object);

    return should_block;
}

_Use_decl_annotations_
BOOLEAN isTextBlocked2(_In_ PFLT_FILTER filter,
                       _In_ PFLT_INSTANCE instance,
                       _In_ PFILE_OBJECT file_object)
{
#ifdef PARANOID_MODE
    if (not filter or
        not instance or
        not file_object)
        return FALSE;
#endif

#ifndef NDEBUG
    if (not file_object->ReadAccess &&
        not file_object->WriteAccess &&
        not file_object->DeleteAccess)
        KdPrint(("WARNING: The file is not open!\n"));

    KdPrint(("[FILE_OBJECT] Flags: 0x%032X\n", file_object->Flags));
#endif

    PFLT_CONTEXT section_context = NULL;
    NTSTATUS status = FltGetSectionContext(instance,
                                           file_object,
                                           &section_context);
    if (not NT_SUCCESS(status) &&
        status != STATUS_NOT_FOUND)
    {
        KdPrint(("Failed to get context: 0x%08X\n", status));
        return FALSE;
    }

    if (section_context != NULL)
    {
        KdPrint(("WARNING: The context already exist!\n"));

        // A section context, FLT_SECTION_CONTEXT type,
        // must not be deleted using FltDeleteContext.
        FltCloseSectionForDataScan(section_context);
        
        FltReleaseContext(section_context);
    }

    status = FltAllocateContext(filter,
                                FLT_SECTION_CONTEXT,
                                MAXUCHAR,
                                NonPagedPool,
                                &section_context);
    if (not NT_SUCCESS(status))
    {
        KdPrint(("Failed to allocate context: 0x%08X\n", status));
        return FALSE;
    }

    HANDLE section_handle;
    PVOID section_object;
    LARGE_INTEGER section_size;
    // WARNING: This routine can only be called on an opened file object!
    status = FltCreateSectionForDataScan(instance,
                                         file_object,
                                         section_context,
                                         SECTION_MAP_READ | SECTION_QUERY,
                                         NULL,
                                         NULL,
                                         PAGE_READONLY,
                                         SEC_COMMIT | SEC_FILE,
                                         0,
                                         &section_handle,
                                         &section_object,
                                         &section_size);
    if (not NT_SUCCESS(status))
    {
#ifndef NDEBUG
        if (status == STATUS_END_OF_FILE)
            KdPrint(("Empty file\n"));
        else
            KdPrint(("Failed to create section: 0x%08X\n", status));
#endif

        FltReleaseContext(section_context);

        return FALSE;
    }

    BOOLEAN should_block = FALSE;

    PVOID base_address = NULL;
    SIZE_T view_size = 0;
    status = ZwMapViewOfSection(section_handle,
                                ZwCurrentProcess(),
                                &base_address,
                                0,
                                0,
                                NULL,
                                &view_size,
                                ViewUnmap,
                                0,
                                PAGE_READONLY);
    if (not NT_SUCCESS(status))
    {
        KdPrint(("Failed to map view: 0x%08X\n", status));
        goto End;
    }

    UTF8_STRING utf8_string = {
        .Buffer = (PCHAR)base_address,
        .Length = (USHORT)MIN(section_size.QuadPart,
                              fb_config.text_to_block.Length),
        .MaximumLength = (USHORT)MIN(section_size.QuadPart,
                                     (LONGLONG)view_size)
    };

    NT_VERIFY(utf8_string.Length <= utf8_string.MaximumLength);

    KdPrint(("String size: %hu/%hu bytes\n", utf8_string.Length,          // нужно прочитать
                                             utf8_string.MaximumLength)); // можно прочитать

    UNICODE_STRING unicode_string;
    status = RtlUTF8StringToUnicodeString(&unicode_string, &utf8_string, TRUE);
    if (NT_SUCCESS(status))
    {
        should_block = RtlPrefixUnicodeString(&fb_config.text_to_block,
                                              &unicode_string,
                                              TRUE);

        RtlFreeUnicodeString(&unicode_string);
    }
    else
    {
        KdPrint(("Failed to convert string: 0x%08X\n", status));
    }

    ZwUnmapViewOfSection(ZwCurrentProcess(), base_address);

End:
    ZwClose(section_handle);
    ObDereferenceObject(section_object);

    FltCloseSectionForDataScan(section_context);

    FltReleaseContext(section_context);

    return should_block;
}
#endif
