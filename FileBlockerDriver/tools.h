#include <ntdef.h>

BOOLEAN initializeFileBlocker(_In_ PDRIVER_OBJECT driver_object,
                              _In_ PUNICODE_STRING registry_key_path);
VOID uninitializeFileBlocker();

BOOLEAN isRecycleBinPath(_In_reads_bytes_(file_name_len) PWCH file_name,
                         _In_ ULONG file_name_len);

BOOLEAN isExtensionBlocked(_In_ PCUNICODE_STRING file_name);
BOOLEAN isTextBlocked(_In_ UNICODE_STRING file_name);
