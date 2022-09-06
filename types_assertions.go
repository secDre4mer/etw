//go:build checkcgostructs

package etw

/*
// MinGW headers are always restricted to the lowest possible Windows version,
// so specify Win7+ manually.
#undef _WIN32_WINNT
#define _WIN32_WINNT _WIN32_WINNT_WIN7

#include <windows.h>
#include <evntcons.h>
#include <tdh.h>
*/
import "C"

import "unsafe"

// This file contains compile time assertions about the sizes of the go structs that we define.
// These structs must match the equivalent C structs in size. If they don't, some API calls will fail.
// This is ensured here by subtracting their sizes into an (ignored) uintptr value; if the sizes differ,
// one of the subtraction results will be negative and thus overflow uintptr, leading to a compile error.

// These assertions are static for each architecture and do not change as long as the structs remain unchanged.
// If you need to check these assertions (due to new structs or struct changes) compile the package with the
// checkcgostructs tag.

const (
	_ = unsafe.Sizeof(eventHeaderC{}) - unsafe.Sizeof(C.EVENT_HEADER{})
	_ = unsafe.Sizeof(C.EVENT_HEADER{}) - unsafe.Sizeof(eventHeaderC{})
)

const (
	_ = unsafe.Sizeof(eventRecordC{}) - unsafe.Sizeof(C.EVENT_RECORD{})
	_ = unsafe.Sizeof(C.EVENT_RECORD{}) - unsafe.Sizeof(eventRecordC{})
)

const (
	_ = unsafe.Offsetof(traceEventInfoC{}.TopLevelPropertyCount) - unsafe.Offsetof(C.TRACE_EVENT_INFO{}.TopLevelPropertyCount)
	_ = unsafe.Offsetof(C.TRACE_EVENT_INFO{}.TopLevelPropertyCount) - unsafe.Offsetof(traceEventInfoC{}.TopLevelPropertyCount)
)

const (
	_ = unsafe.Sizeof(eventPropertyInfoC{}) - unsafe.Sizeof(C.EVENT_PROPERTY_INFO{})
	_ = unsafe.Sizeof(C.EVENT_PROPERTY_INFO{}) - unsafe.Sizeof(eventPropertyInfoC{})
)

const (
	_ = unsafe.Sizeof(eventTraceLogfile{}) - unsafe.Sizeof(C.EVENT_TRACE_LOGFILEW{})
	_ = unsafe.Sizeof(C.EVENT_TRACE_LOGFILEW{}) - unsafe.Sizeof(eventTraceLogfile{})
)

const (
	_ = unsafe.Sizeof(traceLogfileHeader{}) - unsafe.Sizeof(C.TRACE_LOGFILE_HEADER{})
	_ = unsafe.Sizeof(C.TRACE_LOGFILE_HEADER{}) - unsafe.Sizeof(traceLogfileHeader{})
)

const (
	_ = unsafe.Sizeof(eventTrace{}) - unsafe.Sizeof(C.EVENT_TRACE{})
	_ = unsafe.Sizeof(C.EVENT_TRACE{}) - unsafe.Sizeof(eventTrace{})
)

const (
	_ = unsafe.Sizeof(eventTraceHeader{}) - unsafe.Sizeof(C.EVENT_TRACE_HEADER{})
	_ = unsafe.Sizeof(C.EVENT_TRACE_HEADER{}) - unsafe.Sizeof(eventTraceHeader{})
)

const (
	_ = unsafe.Sizeof(eventTraceProperties{}) - unsafe.Sizeof(C.EVENT_TRACE_PROPERTIES{})
	_ = unsafe.Sizeof(C.EVENT_TRACE_PROPERTIES{}) - unsafe.Sizeof(eventTraceProperties{})
)

const (
	_ = unsafe.Sizeof(wnodeHeader{}) - unsafe.Sizeof(C.WNODE_HEADER{})
	_ = unsafe.Sizeof(C.WNODE_HEADER{}) - unsafe.Sizeof(wnodeHeader{})
)

const (
	_ = unsafe.Sizeof(eventFilterDescriptorC{}) - unsafe.Sizeof(C.EVENT_FILTER_DESCRIPTOR{})
	_ = unsafe.Sizeof(C.EVENT_FILTER_DESCRIPTOR{}) - unsafe.Sizeof(eventFilterDescriptorC{})
)

const (
	_ = unsafe.Sizeof(enableTraceParameters{}) - unsafe.Sizeof(C.ENABLE_TRACE_PARAMETERS{})
	_ = unsafe.Sizeof(C.ENABLE_TRACE_PARAMETERS{}) - unsafe.Sizeof(enableTraceParameters{})
)
