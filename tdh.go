package etw

/*
	#include "session.h"
*/
import "C"
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

const (
	_ = unsafe.Sizeof(eventHeaderC{}) - unsafe.Sizeof(C.EVENT_HEADER{})
	_ = unsafe.Sizeof(C.EVENT_HEADER{}) - unsafe.Sizeof(eventHeaderC{})
)

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
const anysizeArray = 1 << 28

type eventRecordC struct {
	EventHeader       eventHeaderC
	BufferContext     etwBufferContext
	ExtendedDataCount uint16
	UserDataLength    uint16
	ExtendedData      *[anysizeArray]eventHeaderExtendedDataItem
	UserData          unsafe.Pointer
	UserContext       uintptr
}

const (
	_ = unsafe.Offsetof(eventRecordC{}.UserContext) - unsafe.Offsetof(C.EVENT_RECORD{}.UserContext)
	_ = unsafe.Offsetof(C.EVENT_RECORD{}.UserContext) - unsafe.Offsetof(eventRecordC{}.UserContext)
)

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

const (
	_ = unsafe.Offsetof(traceEventInfoC{}.TopLevelPropertyCount) - unsafe.Offsetof(C.TRACE_EVENT_INFO{}.TopLevelPropertyCount)
	_ = unsafe.Offsetof(C.TRACE_EVENT_INFO{}.TopLevelPropertyCount) - unsafe.Offsetof(traceEventInfoC{}.TopLevelPropertyCount)
)

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

const (
	_ = unsafe.Sizeof(eventPropertyInfoC{}) - unsafe.Sizeof(C.EVENT_PROPERTY_INFO{})
	_ = unsafe.Sizeof(C.EVENT_PROPERTY_INFO{}) - unsafe.Sizeof(eventPropertyInfoC{})
)

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
