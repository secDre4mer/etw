//go:build windows
// +build windows

// Package etw allows you to receive Event Tracing for Windows (ETW) events.
//
// etw allows you to process events from new TraceLogging providers as well as
// from classic (aka EventLog) providers, so you could actually listen to
// anything you can see in Event Viewer window.
//
// For possible usage examples take a look at
// https://github.com/bi-zone/etw/tree/master/examples
package etw

/*
	#cgo LDFLAGS: -ltdh

	#include "session.h"
*/
import "C"
import (
	"fmt"
	"math"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	advapi32 = windows.NewLazySystemDLL("advapi32.dll")

	traceSetInformation   = advapi32.NewProc("TraceSetInformation")
	traceQueryInformation = advapi32.NewProc("TraceQueryInformation")
)

// ExistsError is returned by NewSession if the session name is already taken.
//
// Having ExistsError you have an option to force kill the session:
//
//	var exists etw.ExistsError
//	s, err = etw.NewSession(s.guid, etw.WithName(sessionName))
//	if errors.As(err, &exists) {
//		err = etw.KillSession(exists.SessionName)
//	}
type ExistsError struct{ SessionName string }

func (e ExistsError) Error() string {
	return fmt.Sprintf("session %q already exist", e.SessionName)
}

// Session represents a Windows event tracing session that is ready to start
// events processing. Session subscribes to the given ETW provider only on
// `.Process`  call, so having a Session without `.Process` called should not
// affect OS performance.
//
// Session should be closed via `.Close` call to free obtained OS resources
// even if `.Process` has never been called.
type Session struct {
	guids    []windows.GUID
	config   SessionOptions
	callback EventCallback

	etwSessionName []uint16
	hSession       C.TRACEHANDLE
	propertiesBuf  []byte

	processedEvents uint64
}

// EventCallback is any function that could handle an ETW event. EventCallback
// is called synchronously and sequentially on every event received by Session
// one by one.
//
// If EventCallback can't handle all ETW events produced, OS will handle a
// tricky file-based cache for you, however, it's recommended not to perform
// long-running tasks inside a callback.
//
// N.B. Event pointer @e is valid ONLY inside a callback. You CAN'T copy a
// whole event, only EventHeader, EventProperties and ExtendedEventInfo
// separately.
type EventCallback func(e *Event)

// NewSession creates a Windows event tracing session instance. Session with no
// options provided is a usable session, but it could be a bit noisy. It's
// recommended to refine the session with level and match keywords options
// to get rid of unnecessary events.
//
// You MUST call `.Close` on session after use to clear associated resources,
// otherwise it will leak in OS internals until system reboot.
func NewSession(options ...SessionOption) (*Session, error) {
	defaultConfig := SessionOptions{
		Name: "go-etw-" + randomName(),
	}
	for _, opt := range options {
		opt(&defaultConfig)
	}
	s := Session{
		config: defaultConfig,
	}

	if err := s.createETWSession(); err != nil {
		return nil, err
	}
	// TODO: consider setting a finalizer with .Close

	return &s, nil
}

// Update updates the session options with the new options.
// It is not possible to update the name of a session.
// Changing log file modes may also fail.
func (s *Session) Update(options ...SessionOption) error {
	var newConfig SessionOptions
	for _, opt := range options {
		opt(&newConfig)
	}
	return s.updateSessionProperties(newConfig)
}

// AddProvider adds a provider to the session. This can also be used to change subscription parameters.
func (s *Session) AddProvider(providerGUID windows.GUID, options ...ProviderOption) error {
	defaultConfig := ProviderOptions{
		Level: TRACE_LEVEL_VERBOSE,
	}
	for _, opt := range options {
		opt(&defaultConfig)
	}

	if err := s.subscribeToProvider(providerGUID, defaultConfig); err != nil {
		return fmt.Errorf("failed to subscribe to provider; %w", err)
	}
	s.guids = append(s.guids, providerGUID)
	return nil
}

// Process starts processing of ETW events. Events will be passed to @cb
// synchronously and sequentially. Take a look to EventCallback documentation
// for more info about events processing.
//
// N.B. Process blocks until `.Close` being called!
func (s *Session) Process(cb EventCallback) error {
	s.callback = cb

	cgoKey := newCallbackKey(s)
	defer freeCallbackKey(cgoKey)

	// Will block here until being closed.
	if err := s.processEvents(cgoKey); err != nil {
		return fmt.Errorf("error processing events; %w", err)
	}
	return nil
}

type SessionStatistics struct {
	LostEvents      uint64
	ProcessedEvents uint64
}

// Stat queries runtime information about the session.
func (s *Session) Stat() (SessionStatistics, error) {
	sessionProperties, err := s.querySessionDetails()
	if err != nil {
		return SessionStatistics{}, fmt.Errorf("could not query session details: %w", err)
	}
	return SessionStatistics{
		LostEvents:      uint64(sessionProperties.EventsLost),
		ProcessedEvents: s.processedEvents,
	}, nil
}

// Close stops trace session and frees associated resources.
func (s *Session) Close() error {
	// "Be sure to disable all providers before stopping the session."
	// https://docs.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-an-event-tracing-session
	if err := s.unsubscribeFromProviders(); err != nil {
		s.stopSession()
		return fmt.Errorf("failed to disable provider; %w", err)
	}

	if err := s.stopSession(); err != nil {
		return fmt.Errorf("failed to stop session; %w", err)
	}
	return nil
}

// KillSession forces the session with a given @name to stop. Don't having a
// session handle we can't shutdown it gracefully unsubscribing from all the
// providers first, so we just stop the session itself.
//
// Use KillSession only to destroy session you've lost control over. If you
// have a session handle always prefer `.Close`.
func KillSession(name string) error {
	nameUTF16, err := windows.UTF16FromString(name)
	if err != nil {
		return fmt.Errorf("failed to convert session name to utf16; %w", err)
	}
	sessionNameLength := len(nameUTF16) * int(unsafe.Sizeof(nameUTF16[0]))

	//
	// For a graceful shutdown we should unsubscribe from all providers associated
	// with the session, but we can't find a way to query them using WinAPI.
	// So we just ask the session to stop and hope that wont hurt anything too bad.
	//

	// We don't know if this session was opened with the log file or not
	// (session could be opened without our library) so allocate memory for LogFile name too.
	const maxLengthLogfileName = 1024
	bufSize := int(unsafe.Sizeof(C.EVENT_TRACE_PROPERTIES{})) + sessionNameLength + maxLengthLogfileName
	propertiesBuf := make([]byte, bufSize)
	pProperties := (C.PEVENT_TRACE_PROPERTIES)(unsafe.Pointer(&propertiesBuf[0]))
	pProperties.Wnode.BufferSize = C.ulong(bufSize)

	// ULONG WMIAPI ControlTraceW(
	//  TRACEHANDLE             TraceHandle,
	//  LPCWSTR                 InstanceName,
	//  PEVENT_TRACE_PROPERTIES Properties,
	//  ULONG                   ControlCode
	// );
	ret := C.ControlTraceW(
		0,
		(*C.ushort)(unsafe.Pointer(&nameUTF16[0])),
		pProperties,
		C.EVENT_TRACE_CONTROL_STOP)

	// If you receive ERROR_MORE_DATA when stopping the session, ETW will have
	// already stopped the session before generating this error.
	// https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-controltracew
	switch status := windows.Errno(ret); status {
	case windows.ERROR_MORE_DATA, windows.ERROR_SUCCESS:
		return nil
	default:
		return status
	}
}

func (s *Session) generateTraceProperties(config SessionOptions) []byte {
	var logFileMode C.ULONG
	for _, mode := range config.LogFileModes {
		if !(mode == EVENT_TRACE_SYSTEM_LOGGER_MODE && getWindowsVersion() <= windows7) {
			logFileMode |= C.ULONG(mode)
		}
	}
	// Mark that we are going to process events in real time using a callback.
	logFileMode |= C.EVENT_TRACE_REAL_TIME_MODE

	// We need to allocate a sequential buffer for a structure and a session name
	// which will be placed there by an API call (for the future calls).
	//
	// (Ref: https://docs.microsoft.com/en-us/windows/win32/etw/wnode-header#members)
	//
	// The only way to do it in go -- unsafe cast of the allocated memory.
	sessionNameSize := len(s.etwSessionName) * int(unsafe.Sizeof(s.etwSessionName[0]))
	bufSize := int(unsafe.Sizeof(C.EVENT_TRACE_PROPERTIES{})) + sessionNameSize
	propertiesBuf := make([]byte, bufSize)

	// We will use Query Performance Counter for timestamp cos it gives us higher
	// time resolution. Event timestamps however would be converted to the common
	// FileTime due to absence of PROCESS_TRACE_MODE_RAW_TIMESTAMP in LogFileMode.
	//
	// Ref: https://docs.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties
	pProperties := (C.PEVENT_TRACE_PROPERTIES)(unsafe.Pointer(&propertiesBuf[0]))
	pProperties.Wnode.BufferSize = C.ulong(bufSize)
	pProperties.Wnode.ClientContext = 1 // QPC for event Timestamp
	pProperties.Wnode.Flags = C.WNODE_FLAG_TRACED_GUID

	pProperties.LogFileMode = logFileMode

	var enableFlags C.ULONG
	for _, flag := range config.Flags {
		if !traceSetInformationFlags[flag] {
			enableFlags |= C.ULONG(flag)
		}
	}
	pProperties.EnableFlags = enableFlags
	return propertiesBuf
}

// createETWSession wraps StartTraceW.
func (s *Session) createETWSession() error {
	utf16Name, err := windows.UTF16FromString(s.config.Name)
	if err != nil {
		return fmt.Errorf("incorrect session name; %w", err) // unlikely
	}
	s.etwSessionName = utf16Name
	for _, mode := range s.config.LogFileModes {
		if mode == EVENT_TRACE_SYSTEM_LOGGER_MODE && getWindowsVersion() <= windows7 {
			// We are on Windows 7 or older. These versions do not support EVENT_TRACE_SYSTEM_LOGGER_MODE
			// and instead requires usage of the global kernel logger session.
			s.etwSessionName, _ = windows.UTF16FromString(C.KERNEL_LOGGER_NAME)
		}
	}
	propertiesBuf := s.generateTraceProperties(s.config)

	ret := C.StartTraceW(
		&s.hSession,
		C.LPWSTR(unsafe.Pointer(&s.etwSessionName[0])),
		C.PEVENT_TRACE_PROPERTIES(unsafe.Pointer(&propertiesBuf[0])),
	)
	switch err := windows.Errno(ret); err {
	case windows.ERROR_ALREADY_EXISTS:
		return ExistsError{SessionName: s.config.Name}
	case windows.ERROR_SUCCESS:
		s.propertiesBuf = propertiesBuf
	default:
		return fmt.Errorf("StartTraceW failed; %w", err)
	}

	if err := s.setEnableFlags(s.config.Flags); err != nil {
		s.Close()
		return fmt.Errorf("failed to set flags; %w", err)
	}
	return nil
}

func (s *Session) setEnableFlags(flags []EnableFlag) error {
	var activateRundown bool
	var traceSetInfoFlags C.ULONG
	for _, flag := range flags {
		if traceSetInformationFlags[flag] {
			traceSetInfoFlags |= C.ULONG(flag)
		}
		if flag == EVENT_TRACE_FLAG_RUNDOWN {
			activateRundown = true
		}
	}
	if traceSetInfoFlags == 0 && !activateRundown {
		return nil
	}
	if err := traceSetInformation.Find(); err != nil {
		return fmt.Errorf("TraceSetInformation is only supported on Windows 8+")
	}
	if err := traceQueryInformation.Find(); err != nil {
		return fmt.Errorf("TraceQueryInformation is only supported on Windows 8+")
	}
	var masks perfinfoGroupmask
	ret, _, _ := traceQueryInformation.Call(
		uintptr(s.hSession),
		uintptr(C.TraceSystemTraceEnableFlagsInfo),
		uintptr(unsafe.Pointer(&masks)),
		unsafe.Sizeof(masks),
		0,
	)
	if err := windows.Errno(ret); err != windows.ERROR_SUCCESS {
		return fmt.Errorf("TraceQueryInformation failed; %w", err)
	}
	if activateRundown {
		var emptyMask perfinfoGroupmask
		ret, _, _ = traceSetInformation.Call(
			uintptr(s.hSession),
			uintptr(C.TraceSystemTraceEnableFlagsInfo),
			uintptr(unsafe.Pointer(&emptyMask)),
			unsafe.Sizeof(emptyMask),
		)
		if err := windows.Errno(ret); err != windows.ERROR_SUCCESS {
			return fmt.Errorf("TraceSetInformation failed; %w", err)
		}
	}

	masks[4] = traceSetInfoFlags

	ret, _, _ = traceSetInformation.Call(
		uintptr(s.hSession),
		uintptr(C.TraceSystemTraceEnableFlagsInfo),
		uintptr(unsafe.Pointer(&masks)),
		unsafe.Sizeof(masks),
	)
	if err := windows.Errno(ret); err != windows.ERROR_SUCCESS {
		return fmt.Errorf("TraceSetInformation failed; %w", err)
	}
	return nil
}

type perfinfoGroupmask [8]C.ULONG

func (s *Session) updateSessionProperties(config SessionOptions) error {
	propertiesBuf := s.generateTraceProperties(config)

	ret := C.ControlTraceW(
		s.hSession,
		C.LPWSTR(unsafe.Pointer(&s.etwSessionName[0])),
		C.PEVENT_TRACE_PROPERTIES(unsafe.Pointer(&propertiesBuf[0])),
		C.EVENT_TRACE_CONTROL_UPDATE,
	)
	if err := windows.Errno(ret); err != windows.ERROR_SUCCESS {
		return fmt.Errorf("ControlTraceW failed; %w", err)
	}
	if err := s.setEnableFlags(config.Flags); err != nil {
		// Try to revert changes made with ControlTraceW
		// by reverting to the old, stored propertiesBuf
		C.ControlTraceW(
			s.hSession,
			C.LPWSTR(unsafe.Pointer(&s.etwSessionName[0])),
			C.PEVENT_TRACE_PROPERTIES(unsafe.Pointer(&s.propertiesBuf[0])),
			C.EVENT_TRACE_CONTROL_UPDATE,
		)
		return fmt.Errorf("failed to set flags; %w", err)
	}
	s.propertiesBuf = propertiesBuf
	s.config = config
	return nil
}

// subscribeToProvider wraps EnableTraceEx2 with EVENT_CONTROL_CODE_ENABLE_PROVIDER.
func (s *Session) subscribeToProvider(provider windows.GUID, options ProviderOptions) error {
	// https://docs.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-an-event-tracing-session
	params := C.ENABLE_TRACE_PARAMETERS{
		Version: 2, // ENABLE_TRACE_PARAMETERS_VERSION_2
	}
	for _, p := range options.EnableProperties {
		params.EnableProperty |= C.ULONG(p)
	}
	if len(options.Filters) > 0 {
		filtersByType := map[EventFilterType]EventFilter{}
		for _, filter := range options.Filters {
			filterType := filter.Type()
			if existingFilter, typeExists := filtersByType[filterType]; typeExists {
				newFilter, err := filter.Merge(existingFilter)
				if err != nil {
					return fmt.Errorf("could not add filter: %w", err)
				}
				filtersByType[filterType] = newFilter
			} else {
				filtersByType[filterType] = filter
			}
		}
		filterDescriptors := C.malloc(C.size_t(unsafe.Sizeof(C.EVENT_FILTER_DESCRIPTOR{}) * uintptr(len(filtersByType))))
		defer C.free(filterDescriptors)
		filterDescriptorSlice := (*[2 << 25]C.EVENT_FILTER_DESCRIPTOR)(filterDescriptors)
		var index int
		for _, filter := range filtersByType {
			descriptor, err := filter.EventFilterDescriptor()
			if err != nil {
				return err
			}
			if descriptor.Close != nil {
				defer descriptor.Close()
			}
			filterDescriptorSlice[index] = descriptor.Descriptor
			index++
		}
		params.EnableFilterDesc = C.PEVENT_FILTER_DESCRIPTOR(filterDescriptors)
		params.FilterDescCount = C.ULONG(len(filtersByType))
	}

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
	ret := C.EnableTraceEx2(
		s.hSession,
		(*C.GUID)(unsafe.Pointer(&provider)),
		C.EVENT_CONTROL_CODE_ENABLE_PROVIDER,
		C.UCHAR(options.Level),
		C.ULONGLONG(options.MatchAnyKeyword),
		C.ULONGLONG(options.MatchAllKeyword),
		0,       // Timeout set to zero to enable the trace asynchronously
		&params, //nolint:gocritic // TODO: dupSubExpr?? gocritic bug?
	)

	if status := windows.Errno(ret); status != windows.ERROR_SUCCESS {
		return fmt.Errorf("EVENT_CONTROL_CODE_ENABLE_PROVIDER failed for GUID %s; %w", provider, status)
	}

	if options.TriggerRundown {
		ret := C.EnableTraceEx2(
			s.hSession,
			(*C.GUID)(unsafe.Pointer(&provider)),
			C.EVENT_CONTROL_CODE_CAPTURE_STATE,
			C.UCHAR(options.Level),
			C.ULONGLONG(options.MatchAnyKeyword),
			C.ULONGLONG(options.MatchAllKeyword),
			0,
			&params, //nolint:gocritic
		)
		if status := windows.Errno(ret); status != windows.ERROR_SUCCESS {
			return fmt.Errorf("EVENT_CONTROL_CODE_CAPTURE_STATE failed for GUID %s; %w", provider, status)
		}
	}
	return nil
}

// unsubscribeFromProviders wraps EnableTraceEx2 with EVENT_CONTROL_CODE_DISABLE_PROVIDER.
func (s *Session) unsubscribeFromProviders() error {
	var lastError error
	for _, guid := range s.guids {
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
		ret := C.EnableTraceEx2(
			s.hSession,
			(*C.GUID)(unsafe.Pointer(&guid)),
			C.EVENT_CONTROL_CODE_DISABLE_PROVIDER,
			0,
			0,
			0,
			0,
			nil)
		status := windows.Errno(ret)
		if status != windows.ERROR_SUCCESS && status != windows.ERROR_NOT_FOUND {
			lastError = fmt.Errorf("EVENT_CONTROL_CODE_DISABLE_PROVIDER failed for GUID %s; %w", guid, status)
		}
	}
	return lastError
}

// processEvents subscribes to the actual provider events and starts its processing.
func (s *Session) processEvents(callbackContextKey uintptr) error {
	// Ref: https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-opentracew
	traceHandle := C.OpenTraceHelper(
		(C.LPWSTR)(unsafe.Pointer(&s.etwSessionName[0])),
		(C.PVOID)(callbackContextKey),
		C.uintptr_t(handleEventStdcall),
	)
	if C.INVALID_PROCESSTRACE_HANDLE == traceHandle {
		return fmt.Errorf("OpenTraceW failed; %w", windows.GetLastError())
	}

	// BLOCKS UNTIL CLOSED!
	//
	// Ref: https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-processtrace
	// ETW_APP_DECLSPEC_DEPRECATED ULONG WMIAPI ProcessTrace(
	// 	PTRACEHANDLE HandleArray,
	// 	ULONG        HandleCount,
	// 	LPFILETIME   StartTime,
	// 	LPFILETIME   EndTime
	// );
	ret := C.ProcessTrace(
		C.PTRACEHANDLE(&traceHandle),
		1,   // ^ Imagine we pass an array with 1 element here.
		nil, // Do not want to limit StartTime (default is from now).
		nil, // Do not want to limit EndTime.
	)
	switch status := windows.Errno(ret); status {
	case windows.ERROR_SUCCESS, windows.ERROR_CANCELLED:
		return nil // Cancelled is obviously ok when we block until closing.
	default:
		return fmt.Errorf("ProcessTrace failed; %w", status)
	}
}

// stopSession wraps ControlTraceW with EVENT_TRACE_CONTROL_STOP.
func (s *Session) stopSession() error {
	// ULONG WMIAPI ControlTraceW(
	//  TRACEHANDLE             TraceHandle,
	//  LPCWSTR                 InstanceName,
	//  PEVENT_TRACE_PROPERTIES Properties,
	//  ULONG                   ControlCode
	// );
	ret := C.ControlTraceW(
		s.hSession,
		nil,
		(C.PEVENT_TRACE_PROPERTIES)(unsafe.Pointer(&s.propertiesBuf[0])),
		C.EVENT_TRACE_CONTROL_STOP)

	// If you receive ERROR_MORE_DATA when stopping the session, ETW will have
	// already stopped the session before generating this error.
	// https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-controltracew
	switch status := windows.Errno(ret); status {
	case windows.ERROR_MORE_DATA, windows.ERROR_SUCCESS:
		return nil
	default:
		return status
	}
}

// stopSession wraps ControlTraceW with EVENT_TRACE_CONTROL_STOP.
func (s *Session) querySessionDetails() (*C.EVENT_TRACE_PROPERTIES, error) {
	// Allocate a buffer for EVENT_TRACE_PROPERTIES and up to 2 names with up to 1024 chars behind it
	bufSize := int(unsafe.Sizeof(C.EVENT_TRACE_PROPERTIES{}) + 2*1024)
	propertiesBuf := make([]byte, bufSize)

	// We will use Query Performance Counter for timestamp cos it gives us higher
	// time resolution. Event timestamps however would be converted to the common
	// FileTime due to absence of PROCESS_TRACE_MODE_RAW_TIMESTAMP in LogFileMode.
	//
	// Ref: https://docs.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties
	pProperties := (C.PEVENT_TRACE_PROPERTIES)(unsafe.Pointer(&propertiesBuf[0]))
	pProperties.Wnode.BufferSize = C.ulong(bufSize)
	pProperties.LoggerNameOffset = C.ulong(unsafe.Sizeof(C.EVENT_TRACE_PROPERTIES{}))
	pProperties.LogFileNameOffset = C.ulong(unsafe.Sizeof(C.EVENT_TRACE_PROPERTIES{}) + 1024)

	// ULONG WMIAPI ControlTraceW(
	//  TRACEHANDLE             TraceHandle,
	//  LPCWSTR                 InstanceName,
	//  PEVENT_TRACE_PROPERTIES Properties,
	//  ULONG                   ControlCode
	// );
	ret := C.ControlTraceW(
		s.hSession,
		nil,
		(C.PEVENT_TRACE_PROPERTIES)(unsafe.Pointer(&s.propertiesBuf[0])),
		C.EVENT_TRACE_CONTROL_QUERY)

	switch status := windows.Errno(ret); status {
	case windows.ERROR_SUCCESS:
		return pProperties, nil
	default:
		return nil, status
	}
}

func randomName() string {
	if g, err := windows.GenerateGUID(); err == nil {
		return g.String()
	}

	// should be almost impossible, right?
	rand.Seed(time.Now().UnixNano())
	const alph = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 32)
	for i := range b {
		b[i] = alph[rand.Intn(len(alph))]
	}
	return string(b)
}

// We can't pass Go-land pointers to the C-world so we use a classical trick
// storing real pointers inside global map and passing to C "fake pointers"
// which are actually map keys.
//
//nolint:gochecknoglobals
var (
	sessions       sync.Map
	sessionCounter uintptr
)

// newCallbackKey stores a @ptr inside a global storage returning its' key.
// After use the key should be freed using `freeCallbackKey`.
func newCallbackKey(ptr *Session) uintptr {
	key := atomic.AddUintptr(&sessionCounter, 1)
	sessions.Store(key, ptr)

	return key
}

func freeCallbackKey(key uintptr) {
	sessions.Delete(key)
}

var handleEventStdcall = windows.NewCallback(handleEvent)

// handleEvent handles an incoming ETW event. The session is determined by the UserContext key.
func handleEvent(eventRecord *eventRecordC) uintptr {
	key := eventRecord.UserContext
	targetSession, ok := sessions.Load(key)
	if !ok {
		return 0
	}

	session := targetSession.(*Session)
	evt := &Event{
		Header:        eventHeaderToGo(eventRecord.EventHeader),
		eventRecord:   eventRecord,
		ignoreMapInfo: session.config.IgnoreMapInfo,
	}
	session.callback(evt)
	session.processedEvents++
	evt.eventRecord = nil
	return 0
}

func eventHeaderToGo(header eventHeaderC) EventHeader {
	return EventHeader{
		EventDescriptor: header.EventDescriptor,
		ThreadID:        header.ThreadId,
		ProcessID:       header.ProcessId,
		TimeStamp:       stampToTime(header.Timestamp),
		ProviderID:      header.ProviderId,
		ActivityID:      header.ActivityId,

		Flags:         header.Flags,
		KernelTime:    header.KernelTime,
		UserTime:      header.UserTime,
		ProcessorTime: uint64(header.KernelTime) + uint64(header.UserTime)<<32,
	}
}

// stampToTime translates FileTime to a golang time. Same as in standard packages.
func stampToTime(quadPart uint64) time.Time {
	ft := windows.Filetime{
		HighDateTime: uint32(quadPart >> 32),
		LowDateTime:  uint32(quadPart & math.MaxUint32),
	}
	return time.Unix(0, ft.Nanoseconds())
}
