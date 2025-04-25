#pragma once

#ifndef NDEBUG
#include <fltKernel.h>
#else
#include <ntdef.h>
#endif

BOOLEAN checkOsVersion();

#ifndef NDEBUG
VOID printVolumeName(_In_ PFLT_VOLUME volume);
#endif
