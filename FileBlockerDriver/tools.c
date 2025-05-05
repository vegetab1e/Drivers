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

static       UNICODE_STRING REGISTRY_KEY_PATH = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services"
                                                                    L"\\FileBlockerDriver\\Parameters");
static       UNICODE_STRING VALUE_ENTRY_NAME  = RTL_CONSTANT_STRING(L"ConfigPath");

typedef struct _FILE_BLOCKER_CONFIGURATION
{
    UNICODE_STRING ext_to_block;
    UNICODE_STRING text_to_block;
} FILE_BLOCKER_CONFIGURATION, *PFILE_BLOCKER_CONFIGURATION;

static FILE_BLOCKER_CONFIGURATION file_blocker_config;

static BOOLEAN initUnicodeString(PUNICODE_STRING unicode_string)
{
    if (not unicode_string)
        return FALSE;

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

static BOOLEAN getConfigFilePath(_Out_ PUNICODE_STRING config_file_path)
{
    static CHAR buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) +
                       (MAX_PATH_LEN + 1) * sizeof(WCHAR)];

    if (not config_file_path)
        return FALSE;

    OBJECT_ATTRIBUTES object_attributes;
    InitializeObjectAttributes(&object_attributes,
                               &REGISTRY_KEY_PATH,
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

    config_file_path->Buffer = (PWCHAR)value_info->Data;
    config_file_path->Length = (USHORT)(value_info->DataLength - sizeof(WCHAR));
    config_file_path->MaximumLength = config_file_path->Length;

    KdPrint(("Config file path: %wZ\n", config_file_path));
    return TRUE;
}

static VOID parseConfigurationData(_In_ PCCHAR buffer, _In_ USHORT size)
{
    static CONST ANSI_STRING names[] = {
        RTL_CONSTANT_STRING("ext_to_block"),
        RTL_CONSTANT_STRING("text_to_block")
    };

    if ((buffer == NULL) || (size == 0))
        return;

    BOOLEAN is_name = TRUE;
    PUNICODE_STRING value_pointer = NULL;
    for (USHORT i = 0, j = 0; i < size; ++i)
    {
        if (is_name && buffer[i] == '=')
        {
            CONST USHORT name_length = i - j;
            if (name_length)
            {
                CONST ANSI_STRING name = {
                    .Buffer = buffer + j,
                    .Length = name_length,
                    .MaximumLength = name_length
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
                while (i < size && buffer[i] != '\n');

                // до начала следующей непустой строки
                while ((i + 1) < size && (buffer[i + 1] == '\r' || buffer[i + 1] == '\n'))
                {
                    ++i;
                }

                j = i + 1;
                continue;
            }

            j = i + 1;
            is_name = FALSE;
        }
        else if (!is_name && (buffer[i] == '\r' || buffer[i] == '\n' || (i + 1) == size))
        {
            CONST USHORT value_length = i - j;
            if (value_length)
            {
                ANSI_STRING value = {
                    .Buffer = buffer + j,
                    .Length = value_length,
                    .MaximumLength = value_length
                };

                KdPrint(("Parameter value: \"%Z\"\n", value));

                RtlAnsiStringToUnicodeString(value_pointer, &value, FALSE);
            }

            // до начала следующей непустой строки
            while ((i + 1) < size && (buffer[i + 1] == '\r' || buffer[i + 1] == '\n'))
            {
                ++i;
            }

            j = i + 1;
            is_name = TRUE;
            value_pointer = NULL;
        }
    }
}

static BOOLEAN readConfigurationFile()
{
    UNICODE_STRING config_file_path;
    OBJECT_ATTRIBUTES object_attributes;
    InitializeObjectAttributes(&object_attributes,
                               getConfigFilePath(&config_file_path) ? &config_file_path : &CONFIG_FILE_PATH,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    HANDLE file_handle;
    IO_STATUS_BLOCK io_status_block;
    NTSTATUS status = ZwOpenFile(&file_handle,
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

    if (file_standard_info.EndOfFile.QuadPart > MAX_FILE_LEN)
    {
        KdPrint(("File to big\n"));

        ZwClose(file_handle);

        return FALSE;
    }

    PCHAR buffer = MmAllocateNonCachedMemory(file_standard_info.EndOfFile.QuadPart);
    if (not buffer)
    {
        KdPrint(("Failed to allocate memory\n"));

        ZwClose(file_handle);
        
        return FALSE;
    }

    LARGE_INTEGER offset;
    RtlZeroMemory(&offset, sizeof(offset));

    RtlZeroMemory(&io_status_block, sizeof(io_status_block));

    status = ZwReadFile(file_handle,
                        NULL,
                        NULL,
                        NULL,
                        &io_status_block,
                        buffer,
                        (ULONG)file_standard_info.EndOfFile.QuadPart,
                        &offset,
                        NULL);

    ZwClose(file_handle);

    if (not NT_SUCCESS(status))
    {
        KdPrint(("Failed to read file: 0x%08X\n", status));
        return FALSE;
    }

    CONST USHORT num_bytes = (USHORT)io_status_block.Information;
    KdPrint(("Number of bytes read: %hu\n", num_bytes));

    parseConfigurationData(buffer, num_bytes);

    MmFreeNonCachedMemory(buffer, file_standard_info.EndOfFile.QuadPart);

    return TRUE;
}

BOOLEAN initializeFileBlocker()
{
    if (not initUnicodeString(&file_blocker_config.ext_to_block))
        return FALSE;
    
    RtlCopyUnicodeString(&file_blocker_config.ext_to_block, &EXT_TO_BLOCK);

    if (not initUnicodeString(&file_blocker_config.text_to_block))
    {
        ExFreePool(file_blocker_config.ext_to_block.Buffer);
        file_blocker_config.ext_to_block.Buffer = NULL;

        return FALSE;
    }

    RtlCopyUnicodeString(&file_blocker_config.text_to_block, &TEXT_TO_BLOCK);

    readConfigurationFile();

    return TRUE;
}

VOID uninitializeFileBlocker()
{
    if (file_blocker_config.ext_to_block.Buffer)
    {
        ExFreePool(file_blocker_config.ext_to_block.Buffer);
        file_blocker_config.ext_to_block.Buffer = NULL;
    }

    if (file_blocker_config.text_to_block.Buffer)
    {
        ExFreePool(file_blocker_config.text_to_block.Buffer);
        file_blocker_config.text_to_block.Buffer = NULL;
    }
}

BOOLEAN isRecycleBinPath(_In_ PWCH file_name, _In_ ULONG file_name_len)
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
                                 FILE_SHARE_VALID_FLAGS,
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
