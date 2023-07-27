//go:build windows
// +build windows

package etw

// SessionOptions describes Session subscription options.
//
// Most of options will be passed to EnableTraceEx2 and could be refined in
// its docs: https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2
type SessionOptions struct {
	// Name specifies a name of ETW session being created. Further a session
	// could be controlled from other processed by it's name, so it should be
	// unique.
	Name string

	// Ignore any event map information that might have to be parsed from the provider manifest.
	// This can speed up event formatting considerably, but enums or bit maps will no longer
	// be formatted.
	IgnoreMapInfo bool

	// Flags to enable on the session. This is only meaningful for a kernel session.
	Flags []EnableFlag

	LogFileModes []LogFileMode

	Kernel bool

	// Maximum size of the file used to buffer events, in MB
	MaximumFileSize uint32
}

// SessionOption is any function that modifies SessionOptions. Options will be called
// on default config in NewSession. Subsequent options that modifies same
// fields will override each other.
type SessionOption func(cfg *SessionOptions)

// WithName specifies a provided @name for the creating session. Further that
// session could be controlled from other processed by it's name, so it should be
// unique.
func WithName(name string) SessionOption {
	return func(cfg *SessionOptions) {
		cfg.Name = name
	}
}

// IgnoreMapInfo specifies whether event map information should be processed.
// SessionOptions.IgnoreMapInfo has further information on this.
func IgnoreMapInfo(ignoreMapInfo bool) SessionOption {
	return func(cfg *SessionOptions) {
		cfg.IgnoreMapInfo = ignoreMapInfo
	}
}

// EnableFlags enables specific flags that specify which events to receive from a kernel
// session. This option is ignored for non-kernel sessions.
func EnableFlags(flags ...EnableFlag) SessionOption {
	return func(cfg *SessionOptions) {
		cfg.Flags = append(cfg.Flags, flags...)
	}
}

// EnableLogModes sets flags that specify properties of the session.
func EnableLogModes(modes ...LogFileMode) SessionOption {
	return func(cfg *SessionOptions) {
		cfg.LogFileModes = append(cfg.LogFileModes, modes...)
	}
}

// ProviderOptions describes subscription options for a single provider.
type ProviderOptions struct {
	// Level represents provider-defined value that specifies the level of
	// detail included in the event. Higher levels imply that you get lower
	// levels as well. For example, with TRACE_LEVEL_ERROR you'll get all
	// events except ones with level critical. Check `EventDescriptor.Level`
	// values for current event verbosity level.
	Level TraceLevel

	// MatchAnyKeyword is a bitmask of keywords that determine the category of
	// events that you want the provider to write. The provider writes the
	// event if any of the event's keyword bits match any of the bits set in
	// this mask.
	//
	// If MatchAnyKeyword is not set the session will receive ALL possible
	// events (which is equivalent setting all 64 bits to 1).
	//
	// Passed as is to EnableTraceEx2. Refer to its remarks for more info:
	// https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2#remarks
	MatchAnyKeyword uint64

	// MatchAllKeyword is an optional bitmask that further restricts the
	// category of events that you want the provider to write. If the event's
	// keyword meets the MatchAnyKeyword condition, the provider will write the
	// event only if all of the bits in this mask exist in the event's keyword.
	//
	// This mask is not used if MatchAnyKeyword is zero.
	//
	// Passed as is to EnableTraceEx2. Refer to its remarks for more info:
	// https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2#remarks
	MatchAllKeyword uint64

	// EnableProperties defines a set of provider properties consumer wants to
	// enable. Properties adds fields to ExtendedEventInfo or asks provider to
	// sent more events.
	//
	// For more info about available properties check EnableProperty doc and
	// original API reference:
	// https://docs.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-enable_trace_parameters
	EnableProperties []EnableProperty

	// Filters defines a set of filters that limit the events which are sent by the provider.
	// For a full list of possible filters, see here:
	// https://docs.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_filter_descriptor
	// If multiple Filters with the same filter type are specified, they are merged; check the filter
	// type on what can be merged.
	Filters []EventFilter

	// TriggerRundown requests a log of the provider's state information. This typically causes a number
	// of rundown events to be sent at the provider's start.
	TriggerRundown bool
}

// ProviderOption is any function that modifies ProviderOptions. Options will be called
// on default config in NewSession. Subsequent options that modifies same
// fields will override each other.
type ProviderOption func(cfg *ProviderOptions)

// WithLevel specifies a maximum level consumer is interested in. Higher levels
// imply that you get lower levels as well. For example, with TRACE_LEVEL_ERROR
// you'll get all events except ones with level critical.
func WithLevel(lvl TraceLevel) ProviderOption {
	return func(cfg *ProviderOptions) {
		cfg.Level = lvl
	}
}

// WithMatchKeywords allows to specify keywords of receiving events. Each event
// has a set of keywords associated with it. That keywords are encoded as bit
// masks and matched with provided @anyKeyword and @allKeyword values.
//
// A session will receive only those events whose keywords masks has ANY of
// @anyKeyword and ALL of @allKeyword bits sets.
//
// For more info take a look a ProviderOptions docs. To query keywords defined
// by specific provider identified by <GUID> try:
//
//	logman query providers <GUID>
func WithMatchKeywords(anyKeyword, allKeyword uint64) ProviderOption {
	return func(cfg *ProviderOptions) {
		cfg.MatchAnyKeyword = anyKeyword
		cfg.MatchAllKeyword = allKeyword
	}
}

// WithProperty enables additional provider feature toggled by @p. Subsequent
// WithProperty options will enable all provided options.
//
// For more info about available properties check EnableProperty doc and
// original API reference:
// https://docs.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-enable_trace_parameters
func WithProperty(p EnableProperty) ProviderOption {
	return func(cfg *ProviderOptions) {
		cfg.EnableProperties = append(cfg.EnableProperties, p)
	}
}

// WithFilter limits the events that the provider sends. Multiple filters can
// be specified to limit the events even further.
// If multiple Filters with the same filter type are specified, they are merged; check the filter
// type on what can be merged.
func WithFilter(f EventFilter) ProviderOption {
	return func(cfg *ProviderOptions) {
		cfg.Filters = append(cfg.Filters, f)
	}
}

// WithRundown requests a rundown of the current provider state when the provider is added.
func WithRundown(withRundown bool) ProviderOption {
	return func(cfg *ProviderOptions) {
		cfg.TriggerRundown = withRundown
	}
}

// TraceLevel represents provider-defined value that specifies the level of
// detail included in the event. Higher levels imply that you get lower
// levels as well.
type TraceLevel uint8

//nolint:golint,stylecheck // We keep original names to underline that it's an external constants.
const (
	TRACE_LEVEL_CRITICAL    = TraceLevel(1)
	TRACE_LEVEL_ERROR       = TraceLevel(2)
	TRACE_LEVEL_WARNING     = TraceLevel(3)
	TRACE_LEVEL_INFORMATION = TraceLevel(4)
	TRACE_LEVEL_VERBOSE     = TraceLevel(5)
)

// EnableProperty enables a property of a provider session is subscribing for.
//
// For more info about available properties check original API reference:
// https://docs.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-enable_trace_parameters
type EnableProperty uint32

//nolint:golint,stylecheck // We keep original names to underline that it's an external constants.
const (
	// Include in the ExtendedEventInfo the security identifier (SID) of the user.
	EVENT_ENABLE_PROPERTY_SID = EnableProperty(0x001)

	// Include in the ExtendedEventInfo the terminal session identifier.
	EVENT_ENABLE_PROPERTY_TS_ID = EnableProperty(0x002)

	// Include in the ExtendedEventInfo a call stack trace for events written
	// using EventWrite.
	EVENT_ENABLE_PROPERTY_STACK_TRACE = EnableProperty(0x004)

	// Filters out all events that do not have a non-zero keyword specified.
	// By default events with 0 keywords are accepted.
	EVENT_ENABLE_PROPERTY_IGNORE_KEYWORD_0 = EnableProperty(0x010)

	// Filters out all events that are either marked as an InPrivate event or
	// come from a process that is marked as InPrivate. InPrivate implies that
	// the event or process contains some data that would be considered private
	// or personal. It is up to the process or event to designate itself as
	// InPrivate for this to work.
	EVENT_ENABLE_PROPERTY_EXCLUDE_INPRIVATE = EnableProperty(0x200)
)

type EnableFlag uint32

const (
	EVENT_TRACE_FLAG_PROCESS            EnableFlag = 0x00000001
	EVENT_TRACE_FLAG_THREAD             EnableFlag = 0x00000002
	EVENT_TRACE_FLAG_IMAGE_LOAD         EnableFlag = 0x00000004
	EVENT_TRACE_FLAG_DISK_IO            EnableFlag = 0x00000100
	EVENT_TRACE_FLAG_DISK_FILE_IO       EnableFlag = 0x00000200
	EVENT_TRACE_FLAG_MEMORY_PAGE_FAULTS EnableFlag = 0x00001000
	EVENT_TRACE_FLAG_MEMORY_HARD_FAULTS EnableFlag = 0x00002000
	EVENT_TRACE_FLAG_NETWORK_TCPIP      EnableFlag = 0x00010000
	EVENT_TRACE_FLAG_REGISTRY           EnableFlag = 0x00020000
	EVENT_TRACE_FLAG_DBGPRINT           EnableFlag = 0x00040000
	EVENT_TRACE_FLAG_PROCESS_COUNTERS   EnableFlag = 0x00000008
	EVENT_TRACE_FLAG_CSWITCH            EnableFlag = 0x00000010
	EVENT_TRACE_FLAG_DPC                EnableFlag = 0x00000020
	EVENT_TRACE_FLAG_INTERRUPT          EnableFlag = 0x00000040
	EVENT_TRACE_FLAG_SYSTEMCALL         EnableFlag = 0x00000080
	EVENT_TRACE_FLAG_DISK_IO_INIT       EnableFlag = 0x00000400
	EVENT_TRACE_FLAG_ALPC               EnableFlag = 0x00100000
	EVENT_TRACE_FLAG_SPLIT_IO           EnableFlag = 0x00200000
	EVENT_TRACE_FLAG_DRIVER             EnableFlag = 0x00800000
	EVENT_TRACE_FLAG_PROFILE            EnableFlag = 0x01000000
	EVENT_TRACE_FLAG_FILE_IO            EnableFlag = 0x02000000
	EVENT_TRACE_FLAG_FILE_IO_INIT       EnableFlag = 0x04000000
	EVENT_TRACE_FLAG_DISPATCHER         EnableFlag = 0x00000800
	EVENT_TRACE_FLAG_VIRTUAL_ALLOC      EnableFlag = 0x00004000
	EVENT_TRACE_FLAG_VAMAP              EnableFlag = 0x00008000
	EVENT_TRACE_FLAG_NO_SYSCONFIG       EnableFlag = 0x10000000
	EVENT_TRACE_FLAG_JOB                EnableFlag = 0x00080000
	EVENT_TRACE_FLAG_DEBUG_EVENTS       EnableFlag = 0x00400000
	EVENT_TRACE_FLAG_EXTENSION          EnableFlag = 0x80000000
	EVENT_TRACE_FLAG_FORWARD_WMI        EnableFlag = 0x40000000
	EVENT_TRACE_FLAG_ENABLE_RESERVE     EnableFlag = 0x20000000

	EVENT_TRACE_FLAG_OBTRACE EnableFlag = 0x80000040

	// EVENT_TRACE_FLAG_RUNDOWN is not a real flag, but another undefined behavior.
	// Use to cause a call TraceSetInformation with an empty mask, which activates rundown events.
	EVENT_TRACE_FLAG_RUNDOWN EnableFlag = 0x00000000
)

// Map with all events that must be set via the 5th byte in TraceSetInformation instead of the normal EnableFlags
var traceSetInformationFlags = map[EnableFlag]bool{
	EVENT_TRACE_FLAG_OBTRACE: true,
}

type LogFileMode uint32

const (
	// EVENT_TRACE_SECURE_MODE specifies that secure mode should be enabled on the session.
	// This restricts who may log events to the session.
	EVENT_TRACE_SECURE_MODE = LogFileMode(0x00000080)

	// EVENT_TRACE_SYSTEM_LOGGER_MODE specifies that the session will receive events from the
	// SystemTraceProvider.
	EVENT_TRACE_SYSTEM_LOGGER_MODE = LogFileMode(0x02000000)

	// EVENT_TRACE_INDEPENDENT_SESSION_MODE specifies that this session should not be affected
	// by failures in other ETW sessions.
	EVENT_TRACE_INDEPENDENT_SESSION_MODE = LogFileMode(0x08000000)
)

const (
	// kernelLoggerName is the name of the kernel logging ETW session that exists on older machines.
	kernelLoggerName = "NT Kernel Logger"
)
