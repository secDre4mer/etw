package etw

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

func traceQueryInformation(sessionHandle uint64, infoClass traceQueryInfoClass, buffer unsafe.Pointer, bufferSize uint32, returnLength *uint32) error {
	if err := procTraceQueryInformation.Find(); err != nil {
		return fmt.Errorf("TraceQueryInformation is only supported on Windows 8+")
	}
	// ULONG WMIAPI TraceQueryInformation(
	//  [in]            TRACEHANDLE      SessionHandle,
	//  [in]            TRACE_INFO_CLASS InformationClass,
	//  [out]           PVOID            TraceInformation,
	//  [in]            ULONG            InformationLength,
	//  [out, optional] PULONG           ReturnLength
	// );
	ret, _, _ := procTraceQueryInformation.Call(
		// Pass 64-bit argument as lower bits first, then higher bits
		uintptr(sessionHandle),
		uintptr(sessionHandle>>32),
		uintptr(infoClass),
		uintptr(buffer),
		uintptr(bufferSize),
		uintptr(unsafe.Pointer(returnLength)),
	)
	if err := windows.Errno(ret); err != windows.ERROR_SUCCESS {
		return err
	}
	return nil
}

func traceSetInformation(sessionHandle uint64, infoClass traceQueryInfoClass, buffer unsafe.Pointer, bufferSize uint32) error {
	if err := procTraceSetInformation.Find(); err != nil {
		return fmt.Errorf("TraceSetInformation is only supported on Windows 8+")
	}
	// ULONG WMIAPI TraceSetInformation(
	//  [in] TRACEHANDLE      SessionHandle,
	//  [in] TRACE_INFO_CLASS InformationClass,
	//  [in] PVOID            TraceInformation,
	//  [in] ULONG            InformationLength
	// );
	ret, _, _ := procTraceSetInformation.Call(
		// Pass 64-bit argument as lower bits first, then higher bits
		uintptr(sessionHandle),
		uintptr(sessionHandle>>32),
		uintptr(infoClass),
		uintptr(buffer),
		uintptr(bufferSize),
	)
	if err := windows.Errno(ret); err != windows.ERROR_SUCCESS {
		return err
	}
	return nil
}

func controlTrace(sessionHandle uint64, instanceName *uint16, properties *eventTraceProperties, controlCode uint32) error {
	// ULONG WMIAPI ControlTraceW(
	//  TRACEHANDLE             TraceHandle,
	//  LPCWSTR                 InstanceName,
	//  PEVENT_TRACE_PROPERTIES Properties,
	//  ULONG                   ControlCode
	// );
	ret, _, _ := procControlTraceW.Call(
		// Pass 64-bit argument as lower bits first, then higher bits
		uintptr(sessionHandle),
		uintptr(sessionHandle>>32),
		uintptr(unsafe.Pointer(instanceName)),
		uintptr(unsafe.Pointer(properties)),
		uintptr(controlCode),
	)
	if status := windows.Errno(ret); status != windows.ERROR_SUCCESS {
		return status
	}
	return nil
}

func enableTraceEx2(sessionHandle uint64, providerGuid *windows.GUID, controlCode uint32, level TraceLevel, matchAnyKeyword uint64, matchAllKeyword uint64, timeout uint32, enableParameters *enableTraceParameters) error {
	// ULONG WMIAPI EnableTraceEx2(
	//	TRACEHANDLE              TraceHandle,
	//	LPCGUID                  ProviderId,
	//	ULONG                    ControlCode,
	//	UCHAR                    Level,
	//	ULONGLONG                MatchAnyKeyword,
	//	ULONGLONG                MatchAllKeyword,
	//	ULONG                    Timeout,
	//	PENABLE_TRACE_PARAMETERS EnableParameters
	// );
	//
	// Ref: https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2
	ret, _, _ := procEnableTraceEx2.Call(
		// Pass 64-bit argument as lower bits first, then higher bits
		uintptr(sessionHandle),
		uintptr(sessionHandle>>32),
		uintptr(unsafe.Pointer(providerGuid)),
		uintptr(controlCode),
		uintptr(level),
		// Pass 64-bit argument as lower bits first, then higher bits
		uintptr(matchAnyKeyword),
		uintptr(matchAnyKeyword>>32),
		// Pass 64-bit argument as lower bits first, then higher bits
		uintptr(matchAllKeyword),
		uintptr(matchAllKeyword>>32),
		uintptr(timeout),
		uintptr(unsafe.Pointer(enableParameters)),
	)
	if err := windows.Errno(ret); err != windows.ERROR_SUCCESS {
		return err
	}
	return nil
}

func openTrace(logfile *eventTraceLogfile) (uint64, error) {
	// ETW_APP_DECLSPEC_DEPRECATED TRACEHANDLE WMIAPI OpenTraceW(
	//  [in, out] PEVENT_TRACE_LOGFILEW Logfile
	// );
	r1, r2, err := procOpenTraceW.Call(
		uintptr(unsafe.Pointer(logfile)),
	)
	// On 32 bit, r2 contains the upper 32 bits of a 64 bit return value, see
	// https://stackoverflow.com/questions/38738534/what-is-the-second-r2-return-value-in-gos-syscall-for
	traceHandle := uint64(r1) + (uint64(r2) << 32)
	if invalidTraceHandle == traceHandle {
		return 0, err
	}
	return traceHandle, nil
}
