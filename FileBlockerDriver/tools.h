#include <ntdef.h>

BOOLEAN initializeFileBlocker();
VOID uninitializeFileBlocker();

BOOLEAN isRecycleBinPath(_In_ PWCH file_name, _In_ ULONG file_name_len);

BOOLEAN isExtensionBlocked(_In_ PCUNICODE_STRING file_name);
BOOLEAN isTextBlocked(_In_ UNICODE_STRING file_name);
