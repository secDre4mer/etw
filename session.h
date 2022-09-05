// MinGW headers are always restricted to the lowest possible Windows version,
// so specify Win7+ manually.
#undef _WIN32_WINNT
#define _WIN32_WINNT _WIN32_WINNT_WIN7

#include <windows.h>
#include <evntcons.h>
#include <tdh.h>
