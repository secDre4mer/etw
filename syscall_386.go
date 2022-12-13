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
	return traceQueryInformation_32(
		uint32(sessionHandle),
		uint32(sessionHandle>>32),
		infoClass,
		buffer,
		bufferSize,
		returnLength,
	)
}

func traceSetInformation(sessionHandle uint64, infoClass traceQueryInfoClass, buffer unsafe.Pointer, bufferSize uint32) error {
	if err := procTraceSetInformation.Find(); err != nil {
		return fmt.Errorf("TraceSetInformation is only supported on Windows 8+")
	}
	return traceSetInformation_32(
		uint32(sessionHandle),
		uint32(sessionHandle>>32),
		infoClass,
		buffer,
		bufferSize,
	)
}

func controlTrace(sessionHandle uint64, instanceName *uint16, properties *eventTraceProperties, controlCode uint32) error {
	return controlTrace_32(
		uint32(sessionHandle),
		uint32(sessionHandle>>32),
		instanceName,
		properties,
		controlCode,
	)
}

func enableTraceEx2(sessionHandle uint64, providerGuid *windows.GUID, controlCode uint32, level TraceLevel, matchAnyKeyword uint64, matchAllKeyword uint64, timeout uint32, enableParameters *enableTraceParameters) error {
	return enableTraceEx2_32(
		uint32(sessionHandle),
		uint32(sessionHandle>>32),
		providerGuid,
		controlCode,
		level,
		uint32(matchAnyKeyword),
		uint32(matchAnyKeyword>>32),
		uint32(matchAllKeyword),
		uint32(matchAllKeyword>>32),
		timeout,
		enableParameters,
	)
}

func queryProviderFieldInformation(guid *windows.GUID, eventFieldValue uint64, eventFieldType EventFieldType, buffer *providerFieldInfoArray, bufferSize *uint32) error {
	return queryProviderFieldInformation_32(
		guid,
		uint32(eventFieldValue),
		uint32(eventFieldValue>>32),
		eventFieldType,
		buffer,
		bufferSize,
	)
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

func closeTrace(handle uint64) error {
	// ETW_APP_DECLSPEC_DEPRECATED ULONG WMIAPI CloseTrace(
	//  [in] TRACEHANDLE TraceHandle
	// );
	r1, _, _ := procCloseTrace.Call(
		uintptr(handle),
		uintptr(handle>>32),
	)
	err := windows.Errno(r1)
	if err != windows.ERROR_SUCCESS && err != windows.ERROR_CTX_CLOSE_PENDING {
		return err
	}
	return nil
}
