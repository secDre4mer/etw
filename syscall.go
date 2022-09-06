package etw

import (
	"errors"
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

	tdh = windows.NewLazySystemDLL("Tdh.dll")

	procTdhFormatProperty  = tdh.NewProc("TdhFormatProperty")
	procTdhGetPropertySize = tdh.NewProc("TdhGetPropertySize")
	procTdhGetProperty     = tdh.NewProc("TdhGetProperty")

	procEnumerateProviders                = tdh.NewProc("TdhEnumerateProviders")
	procEnumerateProviderFieldInformation = tdh.NewProc("TdhEnumerateProviderFieldInformation")
	procQueryProviderFieldInformation     = tdh.NewProc("TdhQueryProviderFieldInformation")
	procEnumerateManifestProviderEvents   = tdh.NewProc("TdhEnumerateManifestProviderEvents")
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

func enumerateProviderFieldInformation(guid *windows.GUID, fieldType EventFieldType, buffer *providerFieldInfoArray, bufferSize *uint32) error {
	// TDHSTATUS TdhEnumerateProviderFieldInformation(
	//  [in]            LPGUID                    pGuid,
	//  [in]            EVENT_FIELD_TYPE          EventFieldType,
	//  [out, optional] PPROVIDER_FIELD_INFOARRAY pBuffer,
	//  [in, out]       ULONG                     *pBufferSize
	// );
	status, _, _ := procEnumerateProviderFieldInformation.Call(
		uintptr(unsafe.Pointer(guid)),
		uintptr(fieldType),
		uintptr(unsafe.Pointer(buffer)),
		uintptr(unsafe.Pointer(bufferSize)),
	)
	if err := windows.Errno(status); err != windows.ERROR_SUCCESS {
		return err
	}
	return nil
}

func enumerateProviders(buffer *providerEnumerationInfo, bufferSize *uint32) error {
	// TDHSTATUS TdhEnumerateProviders(
	//  [out]     PPROVIDER_ENUMERATION_INFO pBuffer,
	//  [in, out] ULONG                      *pBufferSize
	// );
	status, _, _ := procEnumerateProviders.Call(
		uintptr(unsafe.Pointer(buffer)),
		uintptr(unsafe.Pointer(bufferSize)),
	)
	if err := windows.Errno(status); err != windows.ERROR_SUCCESS {
		return err
	}
	return nil
}

func enumerateManifestProviderEvents(providerGuid *windows.GUID, buffer *providerEventInfo, bufferSize *uint32) error {
	// TDHSTATUS TdhEnumerateManifestProviderEvents(
	//  [in]      LPGUID               ProviderGuid,
	//  [out]     PPROVIDER_EVENT_INFO Buffer,
	//  [in, out] ULONG                *BufferSize
	// );
	if procEnumerateManifestProviderEvents.Find() != nil {
		return errors.New("event listing is only supported on Windows 8.1 and newer")
	}
	status, _, _ := procEnumerateManifestProviderEvents.Call(
		uintptr(unsafe.Pointer(providerGuid)),
		uintptr(unsafe.Pointer(buffer)),
		uintptr(unsafe.Pointer(bufferSize)),
	)
	if err := windows.Errno(status); err != windows.ERROR_SUCCESS {
		return err
	}
	return nil
}
