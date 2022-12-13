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
	hSession       uint64
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

	callbackKey := newCallbackKey(s)
	defer freeCallbackKey(callbackKey)

	// Will block here until being closed.
	if err := s.processEvents(callbackKey); err != nil {
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

const (
	eventTraceControlQuery         = 0
	eventTraceControlStop          = 1
	eventTraceControlUpdate        = 2
	eventTraceControlFlush         = 3
	eventTraceControlIncrementFile = 4
)

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
	bufSize := int(unsafe.Sizeof(eventTraceProperties{})) + sessionNameLength + maxLengthLogfileName
	propertiesBuf := make([]byte, bufSize)
	pProperties := (*eventTraceProperties)(unsafe.Pointer(&propertiesBuf[0]))
	pProperties.Wnode.BufferSize = uint32(bufSize)

	err = controlTrace(
		0,
		&nameUTF16[0],
		pProperties,
		eventTraceControlStop,
	)

	// If you receive ERROR_MORE_DATA when stopping the session, ETW will have
	// already stopped the session before generating this error.
	// https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-controltracew
	if err == windows.ERROR_MORE_DATA {
		err = nil
	}
	return err
}

const (
	eventTraceRealTimeMode = 0x00000100
)

func (s *Session) generateTraceProperties(config SessionOptions) []byte {
	var logFileMode uint32
	for _, mode := range config.LogFileModes {
		if !(mode == EVENT_TRACE_SYSTEM_LOGGER_MODE && getWindowsVersion() <= windows7) {
			logFileMode |= uint32(mode)
		}
	}
	// Mark that we are going to process events in real time using a callback.
	logFileMode |= eventTraceRealTimeMode

	// We need to allocate a sequential buffer for a structure and a session name
	// which will be placed there by an API call (for the future calls).
	//
	// (Ref: https://docs.microsoft.com/en-us/windows/win32/etw/wnode-header#members)
	//
	// The only way to do it in go -- unsafe cast of the allocated memory.
	sessionNameSize := len(s.etwSessionName) * int(unsafe.Sizeof(s.etwSessionName[0]))
	bufSize := int(unsafe.Sizeof(eventTraceProperties{})) + sessionNameSize
	propertiesBuf := make([]byte, bufSize)

	// We will use Query Performance Counter for timestamp cos it gives us higher
	// time resolution. Event timestamps however would be converted to the common
	// FileTime due to absence of PROCESS_TRACE_MODE_RAW_TIMESTAMP in LogFileMode.
	//
	// Ref: https://docs.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties
	pProperties := (*eventTraceProperties)(unsafe.Pointer(&propertiesBuf[0]))
	pProperties.Wnode.BufferSize = uint32(bufSize)
	pProperties.Wnode.ClientContext = 1 // QPC for event Timestamp
	pProperties.Wnode.Flags = wnodeFlagTracedGuid

	pProperties.LogFileMode = logFileMode

	var enableFlags uint32
	for _, flag := range config.Flags {
		if !traceSetInformationFlags[flag] {
			enableFlags |= uint32(flag)
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
			s.etwSessionName, _ = windows.UTF16FromString(kernelLoggerName)
		}
	}
	propertiesBuf := s.generateTraceProperties(s.config)

	err = startTrace(&s.hSession, &s.etwSessionName[0], unsafe.Pointer(&propertiesBuf[0]))
	if err != nil {
		if err == windows.ERROR_ALREADY_EXISTS {
			return ExistsError{SessionName: s.config.Name}
		}
		return fmt.Errorf("StartTraceW failed; %w", err)
	}
	s.propertiesBuf = propertiesBuf

	if err := s.setEnableFlags(s.config.Flags); err != nil {
		s.Close()
		return fmt.Errorf("failed to set flags; %w", err)
	}
	return nil
}

func (s *Session) setEnableFlags(flags []EnableFlag) error {
	var activateRundown bool
	var traceSetInfoFlags uint32
	for _, flag := range flags {
		if traceSetInformationFlags[flag] {
			traceSetInfoFlags |= uint32(flag)
		}
		if flag == EVENT_TRACE_FLAG_RUNDOWN {
			activateRundown = true
		}
	}
	if traceSetInfoFlags == 0 && !activateRundown {
		return nil
	}
	var masks perfinfoGroupmask
	err := traceQueryInformation(
		s.hSession,
		traceSystemTraceEnableFlagsInfo,
		unsafe.Pointer(&masks),
		uint32(unsafe.Sizeof(masks)),
		nil,
	)
	if err != nil {
		return fmt.Errorf("TraceQueryInformation failed; %w", err)
	}
	if activateRundown {
		var emptyMask perfinfoGroupmask
		err := traceSetInformation(
			s.hSession,
			traceSystemTraceEnableFlagsInfo,
			unsafe.Pointer(&emptyMask),
			uint32(unsafe.Sizeof(emptyMask)),
		)
		if err != nil {
			return fmt.Errorf("TraceSetInformation failed; %w", err)
		}
	}

	masks[4] = traceSetInfoFlags

	err = traceSetInformation(
		s.hSession,
		traceSystemTraceEnableFlagsInfo,
		unsafe.Pointer(&masks),
		uint32(unsafe.Sizeof(masks)),
	)
	if err != nil {
		return fmt.Errorf("TraceSetInformation failed; %w", err)
	}
	return nil
}

type perfinfoGroupmask [8]uint32

func (s *Session) updateSessionProperties(config SessionOptions) error {
	propertiesBuf := s.generateTraceProperties(config)

	err := controlTrace(
		s.hSession,
		&s.etwSessionName[0],
		(*eventTraceProperties)(unsafe.Pointer(&propertiesBuf[0])),
		eventTraceControlUpdate,
	)
	if err != nil {
		return fmt.Errorf("ControlTraceW failed; %w", err)
	}
	if err := s.setEnableFlags(config.Flags); err != nil {
		// Try to revert changes made with ControlTraceW
		// by reverting to the old, stored propertiesBuf
		_ = controlTrace(
			s.hSession,
			&s.etwSessionName[0],
			(*eventTraceProperties)(unsafe.Pointer(&propertiesBuf[0])),
			eventTraceControlUpdate,
		)
		return fmt.Errorf("failed to set flags; %w", err)
	}
	s.propertiesBuf = propertiesBuf
	s.config = config
	return nil
}

const (
	eventControlCodeDisableProvider = 0
	eventControlCodeEnableProvider  = 1
	eventControlCodeCaptureState    = 2
)

// subscribeToProvider wraps EnableTraceEx2 with EVENT_CONTROL_CODE_ENABLE_PROVIDER.
func (s *Session) subscribeToProvider(provider windows.GUID, options ProviderOptions) error {
	// https://docs.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-an-event-tracing-session
	var params enableTraceParameters
	params.Version = 2 // ENABLE_TRACE_PARAMETERS_VERSION_2
	for _, p := range options.EnableProperties {
		params.EnableProperty |= uint32(p)
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
		filterDescriptors := make([]eventFilterDescriptorC, len(filtersByType))
		var index int
		for _, filter := range filtersByType {
			descriptor, err := filter.EventFilterDescriptor()
			if err != nil {
				return err
			}
			if descriptor.Close != nil {
				defer descriptor.Close()
			}
			filterDescriptors[index] = descriptor.Descriptor
			index++
		}
		params.EnableFilterDesc = &filterDescriptors[0]
		params.FilterDescCount = uint32(len(filterDescriptors))
	}

	err := enableTraceEx2(
		s.hSession,
		&provider,
		eventControlCodeEnableProvider,
		options.Level,
		options.MatchAnyKeyword,
		options.MatchAllKeyword,
		0, // Timeout set to zero to enable the trace asynchronously
		&params,
	)

	if err != nil {
		return fmt.Errorf("EVENT_CONTROL_CODE_ENABLE_PROVIDER failed for GUID %s; %w", provider, err)
	}

	if options.TriggerRundown {
		err := enableTraceEx2(
			s.hSession,
			&provider,
			eventControlCodeCaptureState,
			options.Level,
			options.MatchAnyKeyword,
			options.MatchAllKeyword,
			0,
			&params,
		)
		if err != nil {
			return fmt.Errorf("EVENT_CONTROL_CODE_CAPTURE_STATE failed for GUID %s; %w", provider, err)
		}
	}
	return nil
}

// unsubscribeFromProviders wraps EnableTraceEx2 with EVENT_CONTROL_CODE_DISABLE_PROVIDER.
func (s *Session) unsubscribeFromProviders() error {
	var lastError error
	for _, guid := range s.guids {
		err := enableTraceEx2(
			s.hSession,
			&guid,
			eventControlCodeDisableProvider,
			0,
			0,
			0,
			0,
			nil,
		)
		if err != nil && err != windows.ERROR_NOT_FOUND {
			lastError = fmt.Errorf("EVENT_CONTROL_CODE_DISABLE_PROVIDER failed for GUID %s; %w", guid, err)
		}
	}
	return lastError
}

const (
	invalidTraceHandle = uint64(windows.InvalidHandle)
)

// processEvents subscribes to the actual provider events and starts its processing.
func (s *Session) processEvents(callbackContextKey uintptr) error {
	// Ref: https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-opentracew
	var trace eventTraceLogfile
	trace.LoggerName = &s.etwSessionName[0]
	trace.Context = callbackContextKey
	trace.ProcessTraceMode = processTraceModeRealTime | processTraceModeEventRecord
	trace.EventCallback = handleEventStdcall

	traceHandle, err := openTrace(&trace)
	if err != nil {
		return fmt.Errorf("OpenTraceW failed; %w", err)
	}
	defer closeTrace(traceHandle)

	// BLOCKS UNTIL CLOSED!
	err = processTrace(&traceHandle, 1, nil, nil)
	if err != nil && err != windows.ERROR_CANCELLED { // Cancelled is obviously ok when we block until closing.
		return fmt.Errorf("ProcessTrace failed; %w", err)
	}
	return nil
}

// stopSession wraps ControlTraceW with EVENT_TRACE_CONTROL_STOP.
func (s *Session) stopSession() error {
	err := controlTrace(
		s.hSession,
		nil,
		(*eventTraceProperties)(unsafe.Pointer(&s.propertiesBuf[0])),
		eventTraceControlStop,
	)

	// If you receive ERROR_MORE_DATA when stopping the session, ETW will have
	// already stopped the session before generating this error.
	// https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-controltracew
	if err == windows.ERROR_MORE_DATA {
		err = nil
	}
	return err
}

// stopSession wraps ControlTraceW with EVENT_TRACE_CONTROL_STOP.
func (s *Session) querySessionDetails() (*eventTraceProperties, error) {
	// Allocate a buffer for EVENT_TRACE_PROPERTIES and up to 2 names with up to 1024 chars behind it
	bufSize := int(unsafe.Sizeof(eventTraceProperties{}) + 2*1024)
	propertiesBuf := make([]byte, bufSize)

	// We will use Query Performance Counter for timestamp cos it gives us higher
	// time resolution. Event timestamps however would be converted to the common
	// FileTime due to absence of PROCESS_TRACE_MODE_RAW_TIMESTAMP in LogFileMode.
	//
	// Ref: https://docs.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties
	pProperties := (*eventTraceProperties)(unsafe.Pointer(&propertiesBuf[0]))
	pProperties.Wnode.BufferSize = uint32(bufSize)
	pProperties.LoggerNameOffset = uint32(unsafe.Sizeof(eventTraceProperties{}))
	pProperties.LogFileNameOffset = uint32(unsafe.Sizeof(eventTraceProperties{}) + 1024)

	err := controlTrace(
		s.hSession,
		nil,
		(*eventTraceProperties)(unsafe.Pointer(&s.propertiesBuf[0])),
		eventTraceControlQuery,
	)
	if err != nil {
		return nil, err
	}
	return pProperties, nil
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

//sys startTrace(sessionHandle *uint64, sessionName *uint16, traceProperties unsafe.Pointer) (ret error) = advapi32.StartTraceW
//sys processTrace(handleArray *uint64, handleCount uint32, startTime *windows.Filetime, endTime *windows.Filetime) (ret error) = advapi32.ProcessTrace

//sys traceQueryInformation_64(sessionHandle uint64, infoClass traceQueryInfoClass, buffer unsafe.Pointer, bufferSize uint32, returnLength *uint32) (ret error) = advapi32.TraceQueryInformation
//sys traceQueryInformation_32(sessionHandleLower uint32, sessionHandleHigher uint32, infoClass traceQueryInfoClass, buffer unsafe.Pointer, bufferSize uint32, returnLength *uint32) (ret error) = advapi32.TraceQueryInformation

//sys traceSetInformation_64(sessionHandle uint64, infoClass traceQueryInfoClass, buffer unsafe.Pointer, bufferSize uint32) (ret error) = advapi32.TraceSetInformation
//sys traceSetInformation_32(sessionHandleLower uint32, sessionHandleHigher uint32, infoClass traceQueryInfoClass, buffer unsafe.Pointer, bufferSize uint32) (ret error) = advapi32.TraceSetInformation

//sys controlTrace_64(sessionHandle uint64, instanceName *uint16, properties *eventTraceProperties, controlCode uint32) (ret error) = advapi32.ControlTraceW
//sys controlTrace_32(sessionHandleLower uint32, sessionHandleHigher uint32, instanceName *uint16, properties *eventTraceProperties, controlCode uint32) (ret error) = advapi32.ControlTraceW

//sys enableTraceEx2_64(sessionHandle uint64, providerGuid *windows.GUID, controlCode uint32, level TraceLevel, matchAnyKeyword uint64, matchAllKeyword uint64, timeout uint32, enableParameters *enableTraceParameters) (ret error) = advapi32.EnableTraceEx2
//sys enableTraceEx2_32(sessionHandleLower uint32, sessionHandleHigher uint32, providerGuid *windows.GUID, controlCode uint32, level TraceLevel, matchAnyKeywordLower uint32, matchAnyKeywordHigher uint32, matchAllKeywordLower uint32, matchAllKeywordHigher uint32, timeout uint32, enableParameters *enableTraceParameters) (ret error) = advapi32.EnableTraceEx2
