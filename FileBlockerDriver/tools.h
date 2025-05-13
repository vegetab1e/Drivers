#pragma once

#ifdef USE_FLT_INSTEAD_ZW
// Подгружает ntdef.h
#include <fltKernel.h>
#else
#include <ntdef.h>
#endif

BOOLEAN initializeFileBlocker(_In_ PDRIVER_OBJECT driver_object,
                              _In_ PUNICODE_STRING registry_key_path);

VOID uninitializeFileBlocker();

BOOLEAN isRecycleBinPath(_In_reads_bytes_(file_name_len) PWCH file_name,
                         _In_ ULONG file_name_len);

BOOLEAN isExtensionBlocked(_In_ PCUNICODE_STRING file_name);

#ifndef USE_FLT_INSTEAD_ZW
BOOLEAN isTextBlocked(_In_ UNICODE_STRING file_name);
#else
BOOLEAN isTextBlocked(_In_ PFLT_FILTER filter,
                      _In_ PFLT_INSTANCE instance,
#ifndef NDEBUG
                      _In_opt_ PFILE_OBJECT in_file_object,
#endif
                      _In_ UNICODE_STRING file_name);
BOOLEAN isTextBlocked2(_In_ PFLT_FILTER filter,
                       _In_ PFLT_INSTANCE instance,
                       _In_ PFILE_OBJECT file_object);
#endif
