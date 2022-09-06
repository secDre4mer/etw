package etw

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// This file contains struct definitions to match the C structs used by the event tracing API.

type eventHeaderC struct {
	Size            uint16
	HeaderType      uint16
	Flags           uint16
	EventProperty   uint16
	ThreadId        uint32
	ProcessId       uint32
	Timestamp       uint64
	ProviderId      windows.GUID
	EventDescriptor EventDescriptor
	KernelTime      uint32
	UserTime        uint32
	ActivityId      windows.GUID
}

type etwBufferContext struct {
	ProcessorIndex uint16
	LoggerId       uint16
}

type eventHeaderExtendedDataItem struct {
	_        uint16
	ExtType  uint16
	_        uint16
	DataSize uint16
	DataPtr  unsafe.Pointer
}

// anysizeArray is a constant that indicates that the referenced array is a variable size array in the C API.
// Since this is a very large value (to avoid running into slice boundaries), structs that contain an anysize array
// should never be instantiated, and only be referred to via pointers.
const anysizeArray = 1 << 25

type eventRecordCommon struct {
	EventHeader       eventHeaderC
	BufferContext     etwBufferContext
	ExtendedDataCount uint16
	UserDataLength    uint16
	ExtendedData      *[anysizeArray]eventHeaderExtendedDataItem
	UserData          unsafe.Pointer
	UserContext       uintptr
}

// EventDescriptor contains low-level metadata that defines received event.
// Most of fields could be used to refine events filtration.
//
// For detailed information about fields values refer to EVENT_DESCRIPTOR docs:
// https://docs.microsoft.com/ru-ru/windows/win32/api/evntprov/ns-evntprov-event_descriptor
type EventDescriptor struct {
	ID      uint16
	Version uint8
	Channel uint8
	Level   uint8
	OpCode  uint8
	Task    uint16
	Keyword uint64
}

type eventExtendedItemStackTrace32 struct {
	MatchId uint64
	Address [anysizeArray]uint32
}

type eventExtendedItemStackTrace64 struct {
	MatchId uint64
	Address [anysizeArray]uint64
}

type traceEventInfoC struct {
	ProviderGuid          windows.GUID
	EventGuid             windows.GUID
	EventDescriptor       EventDescriptor
	DecodingSource        decodingSourceC
	ProviderNameOffset    uint32
	LevelNameOffset       uint32
	ChannelNameOffset     uint32
	KeywordsNameOffset    uint32
	TaskNameOffset        uint32
	OpcodeNameOffset      uint32
	EventMessageOffset    uint32
	ProviderMessageOffset uint32
	BinaryXMLOffset       uint32
	BinaryXMLSize         uint32

	NameOffset uint32 // Union - EventNameOffset and ActivityIDNameOffset

	Offset uint32 // Union - EventAttributesOffset and RelatedActivityIDNameOffset

	PropertyCount          uint32
	TopLevelPropertyCount  uint32
	_                      uint32
	EventPropertyInfoArray [anysizeArray]eventPropertyInfoC
}

type propertyFlagsC uint32

type eventPropertyInfoC struct {
	Flags         propertyFlagsC
	NameOffset    uint32
	nonStructType struct {
		InType        uint16
		OutType       uint16
		MapNameOffset uint32
	}
	countUnion struct {
		count uint16
	}
	lengthUnion struct {
		length uint16
	}
	_ uint32
}

func (e eventPropertyInfoC) countPropertyIndex() uint16 {
	return e.countUnion.count
}

func (e eventPropertyInfoC) count() uint16 {
	return e.countUnion.count
}

func (e eventPropertyInfoC) length() uint16 {
	return e.lengthUnion.length
}

func (e eventPropertyInfoC) lengthPropertyIndex() uint16 {
	return e.lengthUnion.length
}

type structTypeC struct {
	StructStartIndex   uint16
	NumOfStructMembers uint16
	_                  uint32
}

func (e eventPropertyInfoC) structType() structTypeC {
	return structTypeC{
		StructStartIndex:   e.nonStructType.InType,
		NumOfStructMembers: e.nonStructType.OutType,
	}
}

type decodingSourceC uint32 // Enum

const (
	eventHeaderFlagExtendedInfo   = 0x0001
	eventHeaderFlagPrivateSession = 0x0002
	eventHeaderFlagStringOnly     = 0x0004
	eventHeaderFlagTraceMessage   = 0x0008
	eventHeaderFlagNoCputime      = 0x0010
	eventHeaderFlag32BitHeader    = 0x0020
	eventHeaderFlag64BitHeader    = 0x0040
	eventHeaderFlagClassicHeader  = 0x0100
	eventHeaderFlagProcessorIndex = 0x0200
)

const (
	eventHeaderExtTypeRelatedActivityid = 0x0001
	eventHeaderExtTypeSid               = 0x0002
	eventHeaderExtTypeTsId              = 0x0003
	eventHeaderExtTypeInstanceInfo      = 0x0004
	eventHeaderExtTypeStackTrace32      = 0x0005
	eventHeaderExtTypeStackTrace64      = 0x0006
	eventHeaderExtTypePebsIndex         = 0x0007
	eventHeaderExtTypePmcCounters       = 0x0008
	eventHeaderExtTypeMax               = 0x0009
)

const (
	propertyStruct           = 0x1
	propertyParamLength      = 0x2
	propertyParamCount       = 0x4
	propertyWBEMXmlFragment  = 0x8
	propertyParamFixedLength = 0x10
)

type eventTraceLogfileCommon struct {
	LogFileName      *uint16
	LoggerName       *uint16
	CurrentTime      int64
	BuffersRead      uint32
	ProcessTraceMode uint32 // Union - also value for LogFileMode
	CurrentEvent     eventTrace
	LogfileHeader    traceLogfileHeader
	BufferCallback   uintptr
	BufferSize       uint32
	Filled           uint32
	EventsLost       uint32
	EventCallback    uintptr // Union with EventRecordCallback
	IsKernelTrace    uint32
	Context          uintptr
}

type traceLogfileHeader struct {
	BufferSize         uint32
	MajorVersion       uint8
	MinorVersion       uint8
	SubVersion         uint8
	SubMinorVersion    uint8
	ProviderVersion    uint32
	NumberOfProcessors uint32
	EndTime            int64
	TimerResolution    uint32
	MaximumFileSize    uint32
	LogFileMode        uint32
	BuffersWritten     uint32

	// Union with LogInstanceGuid
	StartBuffers  uint32
	PointerSize   uint32
	EventsLost    uint32
	CpuSpeedInMHz uint32

	LoggerName    *uint16
	LogFileName   *uint16
	TimeZone      windows.Timezoneinformation
	_             uint32 // Padding
	BootTime      int64
	PrefFreq      int64
	StartTime     int64
	ReservedFlags uint32
	BuffersLost   uint32
}

type eventTraceCommon struct {
	Header           eventTraceHeader
	InstanceId       uint32
	ParentInstanceId uint32
	ParentGuid       windows.GUID
	MofData          *uint8
	MofLength        uint32
	BufferContext    etwBufferContext // Union with ClientContext
}

type eventTraceHeader struct {
	Size           uint16
	FieldTypeFlags uint16 // Union with HeaderType / MarkerFlags
	Version        uint32 // Union with Type / Level / Version
	ThreadId       uint32
	ProcessId      uint32
	TimeStamp      int64
	Guid           windows.GUID // Union with GuidPtr

	// Union with ProcessorTime and ClientContext / Flags
	KernelTime uint32
	UserTime   uint32
}

const (
	processTraceModeRealTime     = 0x00000100
	processTraceModeRawTimestamp = 0x00001000
	processTraceModeEventRecord  = 0x10000000
)

type eventTracePropertiesCommon struct {
	Wnode               wnodeHeader
	BufferSize          uint32
	MinimumBuffers      uint32
	MaximumBuffers      uint32
	MaximumFileSize     uint32
	LogFileMode         uint32
	FlushTimer          uint32
	EnableFlags         uint32
	_                   int32 // No longer used - AgeLimit / FlushThreshold union
	NumberOfBuffers     uint32
	FreeBuffers         uint32
	EventsLost          uint32
	BuffersWritten      uint32
	LogBuffersLost      uint32
	RealTimeBuffersLost uint32
	LoggerThreadId      windows.Handle
	LogFileNameOffset   uint32
	LoggerNameOffset    uint32

	/* V2 adds:
	VersionNumber       uint32
	FilterDescCount     uint32
	FilterDesc          *eventFilterDescriptorC
	V2Options           uint64
	*/
}

type wnodeHeader struct {
	BufferSize        uint32
	ProviderId        uint32
	HistoricalContext uint64 // Union with Version / Linkage
	TimeStamp         int64  // Union with KernelHandle
	Guid              windows.GUID
	ClientContext     uint32
	Flags             uint32
}

const (
	wnodeFlagAllData             = 0x00000001
	wnodeFlagSingleInstance      = 0x00000002
	wnodeFlagSingleItem          = 0x00000004
	wnodeFlagEventItem           = 0x00000008
	wnodeFlagFixedInstanceSize   = 0x00000010
	wnodeFlagTooSmall            = 0x00000020
	wnodeFlagInstancesSame       = 0x00000040
	wnodeFlagStaticInstanceNames = 0x00000080
	wnodeFlagInternal            = 0x00000100
	wnodeFlagUseTimestamp        = 0x00000200
	wnodeFlagPersistEvent        = 0x00000400
	wnodeFlagEventReference      = 0x00002000
	wnodeFlagAnsiInstancenames   = 0x00004000
	wnodeFlagMethodItem          = 0x00008000
	wnodeFlagPdoInstanceNames    = 0x00010000
	wnodeFlagTracedGuid          = 0x00020000
	wnodeFlagLogWnode            = 0x00040000
	wnodeFlagUseGuidPtr          = 0x00080000
	wnodeFlagUseMofPtr           = 0x00100000
	wnodeFlagNoHeader            = 0x00200000
	wnodeFlagSendDataBlock       = 0x00400000
	wnodeFlagVersionedProperties = 0x00800000
	wnodeFlagSeverityMask        = 0xff000000
)

type eventFilterDescriptorCommon struct {
	Ptr  unsafe.Pointer
	Size uint32
	Type uint32
}

type traceQueryInfoClass uint32

const (
	traceGuidQueryList traceQueryInfoClass = iota
	traceGuidQueryInfo
	traceGuidQueryProcess
	traceStackTracingInfo
	traceSystemTraceEnableFlagsInfo
	traceSampledProfileIntervalInfo
	traceProfileSourceConfigInfo
	traceProfileSourceListInfo
	tracePmcEventListInfo
	tracePmcCounterListInfo
	traceSetDisallowList
	traceVersionInfo
	traceGroupQueryList
	traceGroupQueryInfo
	traceDisallowListQuery
	traceCompressionInfo
	tracePeriodicCaptureStateListInfo
	tracePeriodicCaptureStateInfo
	traceProviderBinaryTracking
	traceMaxLoggersQuery
)

type providerEnumerationInfo struct {
	NumberOfProviders      uint32
	_                      uint32
	TraceProviderInfoArray [anysizeArray]traceProviderInfo
}

type traceProviderInfo struct {
	ProviderGuid       windows.GUID
	SchemaSource       uint32
	ProviderNameOffset uint32
}

// PROVIDER_EVENT_INFO, as described here: https://docs.microsoft.com/en-us/windows/win32/api/tdh/ns-tdh-provider_event_info
type providerEventInfo struct {
	NumberOfEvents uint32
	_              uint32
	descriptors    [anysizeArray]EventDescriptor
}

type providerFieldInfoArray struct {
	NumberOfElements uint32
	FieldType        uint32
	FieldInfoArray   [anysizeArray]providerFieldInfo
}

type providerFieldInfo struct {
	NameOffset        uint32
	DescriptionOffset uint32
	Value             uint64
}
