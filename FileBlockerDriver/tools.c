#include <ntddk.h>

#include <iso646.h>

#include "tools.h"

#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))

#define MAX_PATH_LEN    256
#define MAX_FILE_LEN   1024
#define MAX_STRING_LEN  256

static CONST UNICODE_STRING RECYCLE_BIN_NAME  = RTL_CONSTANT_STRING(L"$RECYCLE.BIN");

static CONST UNICODE_STRING EXT_TO_BLOCK      = RTL_CONSTANT_STRING(L".txt");
static CONST UNICODE_STRING TEXT_TO_BLOCK     = RTL_CONSTANT_STRING(L"This текст should be blocked!");

static       UNICODE_STRING CONFIG_FILE_PATH  = RTL_CONSTANT_STRING(L"\\??\\C:\\config.ini");

static       UNICODE_STRING VALUE_ENTRY_NAME  = RTL_CONSTANT_STRING(L"ConfigFileName");

typedef struct _FILE_BLOCKER_CONFIGURATION
{
    UNICODE_STRING ext_to_block;
    UNICODE_STRING text_to_block;
} FILE_BLOCKER_CONFIGURATION, *PFILE_BLOCKER_CONFIGURATION;

static FILE_BLOCKER_CONFIGURATION file_blocker_config;

static BOOLEAN allocUnicodeString(_Inout_ PUNICODE_STRING unicode_string)
{
#ifdef PARANOID_MODE
    if (not unicode_string)
        return FALSE;
#endif
    if (unicode_string->Buffer)
    {
        KdPrint(("WARNING: String not empty!\n"));

        ExFreePool(unicode_string->Buffer);
    }

    unicode_string->Length = 0;
    unicode_string->MaximumLength = MAX_STRING_LEN * sizeof(WCHAR);
    unicode_string->Buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                             unicode_string->MaximumLength,
                                             '1gaT');
    if (not unicode_string->Buffer)
    {
        KdPrint(("Failed to allocate memory\n"));

        unicode_string->MaximumLength = 0;
        
        return FALSE;
    }

    RtlZeroMemory(unicode_string->Buffer, unicode_string->MaximumLength);

    return TRUE;
}

static VOID freeUnicodeString(_Inout_ PUNICODE_STRING unicode_string)
{
#ifdef PARANOID_MODE
    if (not unicode_string)
        return FALSE;
#endif
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
    if (not allocUnicodeString(&file_blocker_config.ext_to_block))
        return FALSE;

    RtlCopyUnicodeString(&file_blocker_config.ext_to_block, &EXT_TO_BLOCK);

    if (not allocUnicodeString(&file_blocker_config.text_to_block))
    {
        freeUnicodeString(&file_blocker_config.ext_to_block);

        return FALSE;
    }

    RtlCopyUnicodeString(&file_blocker_config.text_to_block, &TEXT_TO_BLOCK);

    return TRUE;
}

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
    status = ZwQueryValueKey(key_handle,
                             &VALUE_ENTRY_NAME,
                             KeyValuePartialInformation,
                             &buffer,
                             length,
                             &length);

    ZwClose(key_handle);

    if (not NT_SUCCESS(status))
    {
        KdPrint(("Failed to query value entry: 0x%08X\n", status));
        return FALSE;
    }

    PKEY_VALUE_PARTIAL_INFORMATION value_info = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;
    if (value_info->Type != REG_EXPAND_SZ)
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

    KdPrint(("Config file name: %wZ\n", config_file_name));
    return TRUE;
}

static VOID parseConfigData(_In_reads_bytes_(length) PCCHAR buffer,
                            _In_ ULONG length)
{
    static CONST ANSI_STRING names[] = {
        RTL_CONSTANT_STRING("ext_to_block"),
        RTL_CONSTANT_STRING("text_to_block")
    };

    if ((buffer == NULL) || (length == 0))
        return;

    BOOLEAN is_name = TRUE;
    ULONG string_length = 0;
    PUNICODE_STRING value_pointer = NULL;
    for (ULONG i = 0, j = 0; i < length; ++i)
    {
        if (is_name && buffer[i] == '=')
        {
            string_length = i - j;
            if (string_length > 0 && string_length <= MAX_STRING_LEN * sizeof(WCHAR))
            {
                CONST ANSI_STRING name = {
                    .Buffer = buffer + j,
                    .Length = (USHORT)string_length,
                    .MaximumLength = (USHORT)string_length
                };

                KdPrint(("Parameter name: \"%Z\"\n", name));

                if (RtlEqualString(&names[0], &name, TRUE))
                    value_pointer = &file_blocker_config.ext_to_block;
                else if (RtlEqualString(&names[1], &name, TRUE))
                    value_pointer = &file_blocker_config.text_to_block;
            }
            
            if (not value_pointer)
            {
                // до конца текущей строки
                do {
                    ++i;
                }
                while (i < length && buffer[i] != '\n');

                // до начала следующей непустой строки
                while ((i + 1) < length && (buffer[i + 1] == '\r' || buffer[i + 1] == '\n'))
                {
                    ++i;
                }

                j = i + 1;
                continue;
            }

            j = i + 1;
            is_name = FALSE;
        }
        else if (!is_name && (buffer[i] == '\r' || buffer[i] == '\n' || (i + 1) == length))
        {
            string_length = i - j;
            if (string_length > 0 && string_length <= MAX_STRING_LEN * sizeof(WCHAR))
            {
                ANSI_STRING value = {
                    .Buffer = buffer + j,
                    .Length = (USHORT)string_length,
                    .MaximumLength = (USHORT)string_length
                };

                KdPrint(("Parameter value: \"%Z\"\n", value));

                RtlAnsiStringToUnicodeString(value_pointer, &value, FALSE);
            }

            // до начала следующей непустой строки
            while ((i + 1) < length && (buffer[i + 1] == '\r' || buffer[i + 1] == '\n'))
            {
                ++i;
            }

            j = i + 1;
            is_name = TRUE;
            value_pointer = NULL;
        }
    }
}

_Success_(return != FALSE)
static BOOLEAN openConfigFile(_In_ HANDLE root_dir_handle,
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
                               root_dir_handle,
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

static ULONG readConfigFile(_In_ HANDLE config_file_handle,
                            _Out_writes_bytes_(length) PCHAR buffer,
                            _In_ ULONG length)
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
        return 0;
    }

    if (file_standard_info.EndOfFile.QuadPart == 0)
    {
        KdPrint(("Empty file\n"));
        return 0;
    }

    if (file_standard_info.EndOfFile.QuadPart > length)
    {
        KdPrint(("File to big\n"));
        return 0;
    }

    LARGE_INTEGER offset = {
        .QuadPart = 0
    };

    RtlZeroMemory(&io_status_block, sizeof(io_status_block));

    status = ZwReadFile(config_file_handle,
                        NULL,
                        NULL,
                        NULL,
                        &io_status_block,
                        buffer,
                        length,
                        &offset,
                        NULL);
    if (not NT_SUCCESS(status))
    {
        KdPrint(("Failed to read file: 0x%08X\n", status));
        return 0;
    }

    return (ULONG)io_status_block.Information;
}

_Use_decl_annotations_
BOOLEAN initializeFileBlocker(_In_ PDRIVER_OBJECT driver_object,
                              _In_ PUNICODE_STRING registry_key_path)
{
    if (not driver_object or
        not registry_key_path)
        return FALSE;

    if (not initDefaultConfig())
        return FALSE;

    HANDLE driver_dir_handle;
    NTSTATUS status = IoGetDriverDirectory(driver_object,
                                           DriverDirectoryImage,
                                           0,
                                           &driver_dir_handle);
    if (not NT_SUCCESS(status))
    {
        KdPrint(("Failed to get driver directory: 0x%08X\n", status));
        goto End;
    }

    UNICODE_STRING config_file_path;
    if (not getConfigFileName(registry_key_path, &config_file_path))
        goto End;

    HANDLE config_file_handle;
    if (not openConfigFile(driver_dir_handle,
                           &config_file_path,
                           &config_file_handle))
        goto End;

    PCHAR buffer = MmAllocateNonCachedMemory(MAX_FILE_LEN);
    if (not buffer)
    {
        KdPrint(("Failed to allocate memory\n"));

        ZwClose(config_file_handle);

        goto End;
    }

    CONST ULONG num_bytes = readConfigFile(config_file_handle,
                                           buffer,
                                           MAX_FILE_LEN);

    MmFreeNonCachedMemory(buffer, MAX_FILE_LEN);
    ZwClose(config_file_handle);

    if (num_bytes)
    {
        KdPrint(("Number of bytes read: %lu\n", num_bytes));

        parseConfigData(buffer, num_bytes);

        KdPrint(("Extension to block: \"%wZ\"\n", file_blocker_config.ext_to_block));
        KdPrint(("Text to block: \"%wZ\"\n", file_blocker_config.text_to_block));

        return TRUE;
    }

End:
    freeUnicodeString(&file_blocker_config.ext_to_block);
    freeUnicodeString(&file_blocker_config.text_to_block);

    return FALSE;
}

VOID uninitializeFileBlocker()
{
    freeUnicodeString(&file_blocker_config.ext_to_block);
    freeUnicodeString(&file_blocker_config.text_to_block);
}

_Use_decl_annotations_
BOOLEAN isRecycleBinPath(_In_reads_bytes_(file_name_len) PWCH file_name,
                         _In_ ULONG file_name_len)
{
    if ((file_name == NULL) ||
        (file_name_len < RECYCLE_BIN_NAME.Length))
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
    if ((file_name == NULL) || (file_name->Buffer == NULL) ||
        (file_name->Length < file_blocker_config.ext_to_block.Length))
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

        return RtlEqualUnicodeString(&file_ext, &file_blocker_config.ext_to_block, TRUE);
    }

    return FALSE;
}

_Use_decl_annotations_
BOOLEAN isTextBlocked(_In_ UNICODE_STRING file_name)
{
    if ((file_name.Buffer == NULL) ||
        (file_name.Length == 0))
        return FALSE;

    OBJECT_ATTRIBUTES object_attributes;
    InitializeObjectAttributes(&object_attributes,
                               &file_name,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    HANDLE file_handle;
    IO_STATUS_BLOCK io_status_block;
    NTSTATUS status = ZwOpenFile(&file_handle,
                                 FILE_GENERIC_READ,
                                 &object_attributes,
                                 &io_status_block,
                                 FILE_SHARE_READ | FILE_SHARE_DELETE,
                                 FILE_NON_DIRECTORY_FILE);
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

    LARGE_INTEGER max_section_size = {
        .QuadPart = MIN(file_standard_info.EndOfFile.QuadPart,
                        file_blocker_config.text_to_block.Length)
    };
    HANDLE section_handle;
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
    
    ANSI_STRING ansi_string = {
        .Buffer = (PCHAR)base_address,
        .Length = (USHORT)max_section_size.QuadPart,
        .MaximumLength = ansi_string.Length
    };
    BOOLEAN should_block = FALSE;
    UNICODE_STRING unicode_string;
    status = RtlAnsiStringToUnicodeString(&unicode_string, &ansi_string, TRUE);
    if (NT_SUCCESS(status))
    {
        should_block = RtlPrefixUnicodeString(&file_blocker_config.text_to_block,
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
