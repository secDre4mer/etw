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
	return traceQueryInformation_64(
		sessionHandle,
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
	return traceSetInformation_64(
		sessionHandle,
		infoClass,
		buffer,
		bufferSize,
	)
}

func controlTrace(sessionHandle uint64, instanceName *uint16, properties *eventTraceProperties, controlCode uint32) error {
	return controlTrace_64(
		sessionHandle,
		instanceName,
		properties,
		controlCode,
	)
}

func enableTraceEx2(sessionHandle uint64, providerGuid *windows.GUID, controlCode uint32, level TraceLevel, matchAnyKeyword uint64, matchAllKeyword uint64, timeout uint32, enableParameters *enableTraceParameters) error {
	return enableTraceEx2_64(
		sessionHandle,
		providerGuid,
		controlCode,
		level,
		matchAnyKeyword,
		matchAllKeyword,
		timeout,
		enableParameters,
	)
}

func queryProviderFieldInformation(guid *windows.GUID, eventFieldValue uint64, eventFieldType EventFieldType, buffer *providerFieldInfoArray, bufferSize *uint32) error {
	return queryProviderFieldInformation_64(
		guid,
		eventFieldValue,
		eventFieldType,
		buffer,
		bufferSize,
	)
}

func openTrace(logfile *eventTraceLogfile) (uint64, error) {
	// ETW_APP_DECLSPEC_DEPRECATED TRACEHANDLE WMIAPI OpenTraceW(
	//  [in, out] PEVENT_TRACE_LOGFILEW Logfile
	// );
	r1, _, err := procOpenTraceW.Call(
		uintptr(unsafe.Pointer(logfile)),
	)
	traceHandle := uint64(r1)
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
	)
	err := windows.Errno(r1)
	if err != windows.ERROR_SUCCESS && err != windows.ERROR_CTX_CLOSE_PENDING {
		return err
	}
	return nil
}
