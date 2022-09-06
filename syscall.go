package etw

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	advapi32 = windows.NewLazySystemDLL("advapi32.dll")

	procTraceSetInformation   = advapi32.NewProc("TraceSetInformation")
	procTraceQueryInformation = advapi32.NewProc("TraceQueryInformation")
	procStartTraceW           = advapi32.NewProc("StartTraceW")
	procControlTraceW         = advapi32.NewProc("ControlTraceW")
	procEnableTraceEx2        = advapi32.NewProc("EnableTraceEx2")
	procOpenTraceW            = advapi32.NewProc("OpenTraceW")
	procProcessTrace          = advapi32.NewProc("ProcessTrace")
)

func startTrace(sessionHandle *uint64, sessionName *uint16, traceProperties unsafe.Pointer) error {
	// ULONG WMIAPI StartTraceW(
	//  [out]     PTRACEHANDLE            TraceHandle,
	//  [in]      LPCWSTR                 InstanceName,
	//  [in, out] PEVENT_TRACE_PROPERTIES Properties
	// );
	ret, _, _ := procStartTraceW.Call(
		uintptr(unsafe.Pointer(sessionHandle)),
		uintptr(unsafe.Pointer(sessionName)),
		uintptr(traceProperties),
	)
	if err := windows.Errno(ret); err != windows.ERROR_SUCCESS {
		return err
	}
	return nil
}

func processTrace(handleArray *uint64, handleCount uint32, startTime *windows.Filetime, endTime *windows.Filetime) error {
	// Ref: https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-processtrace
	// ETW_APP_DECLSPEC_DEPRECATED ULONG WMIAPI ProcessTrace(
	// 	PTRACEHANDLE HandleArray,
	// 	ULONG        HandleCount,
	// 	LPFILETIME   StartTime,
	// 	LPFILETIME   EndTime
	// );
	ret, _, _ := procProcessTrace.Call(
		uintptr(unsafe.Pointer(handleArray)),
		uintptr(handleCount),
		uintptr(unsafe.Pointer(startTime)),
		uintptr(unsafe.Pointer(endTime)),
	)
	if err := windows.Errno(ret); err != windows.ERROR_SUCCESS {
		return err
	}
	return nil
}
