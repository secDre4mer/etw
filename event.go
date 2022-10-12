//go:build windows
// +build windows

package etw

import (
	"fmt"
	"sync"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Event is a single event record received from ETW provider. The only thing
// that is parsed implicitly is an EventHeader (which just translated from C
// structures mostly 1:1), all other data are parsed on-demand.
//
// Events will be passed to the user EventCallback. It's invalid to use Event
// methods outside of an EventCallback.
type Event struct {
	Header        EventHeader
	eventRecord   *eventRecordC
	ignoreMapInfo bool
}

// EventHeader contains an information that is common for every ETW event
// record.
//
// EventHeader fields is self-descriptive. If you need more info refer to the
// original struct docs:
// https://docs.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_header
type EventHeader struct {
	EventDescriptor

	ThreadID  uint32
	ProcessID uint32
	TimeStamp time.Time

	ProviderID windows.GUID
	ActivityID windows.GUID

	Flags         uint16
	KernelTime    uint32
	UserTime      uint32
	ProcessorTime uint64
}

// HasCPUTime returns true if the event has separate UserTime and KernelTime
// measurements. Otherwise the value of UserTime and KernelTime is meaningless
// and you should use ProcessorTime instead.
func (h EventHeader) HasCPUTime() bool {
	switch {
	case h.Flags&eventHeaderFlagNoCputime != 0:
		return false
	case h.Flags&eventHeaderFlagPrivateSession != 0:
		return false
	default:
		return true
	}
}

// UserData returns the payload of the event as a raw slice.
// This data usually needs interpretation, as EventProperties does, to map
// it to single events. However, if for an event the data layout is already
// known, this can be used to efficiently parse the data.
// UserData gives a slice that points directly at the data returned by the API.
// It should not be modified or used after the ETW callback has returned.
func (e *Event) UserData() []byte {
	return unsafe.Slice((*uint8)(e.eventRecord.UserData), e.eventRecord.UserDataLength)
}

// EventProperties returns a map that represents events-specific data provided
// by event producer. Returned data depends on the provider, event type and even
// provider and event versions.
//
// The simplest (and the recommended) way to parse event data is to use TDH
// family of functions that render event data to the strings exactly as you can
// see it in the Event Viewer.
//
// EventProperties returns a map that could be interpreted as "structure that
// fit inside a map". Map keys is a event data field names, map values is field
// values rendered to strings. So map values could be one of the following:
//   - `[]string` for arrays of any types;
//   - `map[string]interface{}` for fields that are structures;
//   - `string` for any other values.
//
// Take a look at `TestParsing` for possible EventProperties values.
func (e *Event) EventProperties() (map[string]interface{}, error) {
	if e.eventRecord == nil {
		return nil, fmt.Errorf("usage of Event is invalid outside of EventCallback")
	}

	if e.eventRecord.EventHeader.Flags == eventHeaderFlagStringOnly {
		return map[string]interface{}{
			"_": zeroTerminatedPointerToString(e.eventRecord.UserData, int(e.eventRecord.UserDataLength)),
		}, nil
	}

	p, err := newPropertyParser(e.eventRecord, e.ignoreMapInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to parse event properties; %w", err)
	}
	defer p.free()

	properties := make(map[string]interface{}, int(p.info.TopLevelPropertyCount))
	for i := 0; i < int(p.info.TopLevelPropertyCount); i++ {
		name := p.getPropertyName(i)
		value, err := p.getPropertyValue(i)
		if err != nil {
			// Parsing values we consume given event data buffer with var length chunks.
			// If we skip any -- we'll lost offset, so fail early.
			return properties, fmt.Errorf("failed to parse %q value; %w", name, err)
		}
		properties[name] = value
	}
	return properties, nil
}

func zeroTerminatedPointerToString(ptr unsafe.Pointer, length int) string {
	array := (*[anysizeArray]uint8)(ptr)[:length]
	var zeroIndex int
	for zeroIndex < len(array) && array[zeroIndex] != 0 {
		zeroIndex++
	}
	return string(array[:zeroIndex])
}

// ExtendedEventInfo contains additional information about received event. All
// ExtendedEventInfo fields are optional and are nils being not set by provider.
//
// Presence of concrete fields is controlled by WithProperty option and an
// ability of event provider to set the required fields.
//
// More info about fields is available at EVENT_HEADER_EXTENDED_DATA_ITEM.ExtType
// documentation:
// https://docs.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_header_extended_data_item
type ExtendedEventInfo struct {
	SessionID    *uint32
	ActivityID   *windows.GUID
	UserSID      *windows.SID
	InstanceInfo *EventInstanceInfo
	StackTrace   *EventStackTrace
}

// EventInstanceInfo defines the relationship between events if its provided.
type EventInstanceInfo struct {
	InstanceID       uint32
	ParentInstanceID uint32
	ParentGUID       windows.GUID
}

// EventStackTrace describes a call trace of the event occurred.
type EventStackTrace struct {
	MatchedID uint64
	Addresses []uint64
}

// ExtendedInfo extracts ExtendedEventInfo structure from native buffers of
// received event record.
//
// If no ExtendedEventInfo is available inside an event record function returns
// the structure with all fields set to nil.
func (e *Event) ExtendedInfo() ExtendedEventInfo {
	if e.eventRecord == nil { // Usage outside of event callback.
		return ExtendedEventInfo{}
	}
	if e.eventRecord.EventHeader.Flags&eventHeaderFlagExtendedInfo == 0 {
		return ExtendedEventInfo{}
	}
	return e.parseExtendedInfo()
}

func (e *Event) parseExtendedInfo() ExtendedEventInfo {
	var extendedData ExtendedEventInfo
	for i := 0; i < int(e.eventRecord.ExtendedDataCount); i++ {
		dataPtr := e.eventRecord.ExtendedData[i].DataPtr

		switch e.eventRecord.ExtendedData[i].ExtType {
		case eventHeaderExtTypeRelatedActivityid:
			guid := *(*windows.GUID)(dataPtr)
			extendedData.ActivityID = &guid

		case eventHeaderExtTypeSid:
			sid := (*windows.SID)(dataPtr)
			sidCopy, err := sid.Copy()
			if err == nil {
				extendedData.UserSID = sidCopy
			}

		case eventHeaderExtTypeTsId:
			sessionId := *(*uint32)(dataPtr)
			extendedData.SessionID = &sessionId

		case eventHeaderExtTypeInstanceInfo:
			instanceInfo := *(*EventInstanceInfo)(dataPtr)
			extendedData.InstanceInfo = &instanceInfo

		case eventHeaderExtTypeStackTrace32:
			stack32 := (*eventExtendedItemStackTrace32)(dataPtr)

			// https://docs.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_extended_item_stack_trace32#remarks
			dataSize := e.eventRecord.ExtendedData[i].DataSize
			matchedIDSize := unsafe.Sizeof(uint64(0))
			arraySize := (uintptr(dataSize) - matchedIDSize) / unsafe.Sizeof(uint32(0))

			address := make([]uint64, arraySize)
			for j := 0; j < int(arraySize); j++ {
				address[j] = uint64(stack32.Address[j])
			}

			extendedData.StackTrace = &EventStackTrace{
				MatchedID: stack32.MatchId,
				Addresses: address,
			}

		case eventHeaderExtTypeStackTrace64:
			stack64 := (*eventExtendedItemStackTrace64)(dataPtr)

			// https://docs.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_extended_item_stack_trace64#remarks
			dataSize := e.eventRecord.ExtendedData[i].DataSize
			matchedIDSize := unsafe.Sizeof(uint64(0))
			arraySize := (uintptr(dataSize) - matchedIDSize) / unsafe.Sizeof(uint64(0))

			address := make([]uint64, arraySize)
			copy(address, stack64.Address[:arraySize])

			extendedData.StackTrace = &EventStackTrace{
				MatchedID: stack64.MatchId,
				Addresses: address,
			}

			// TODO:
			// EVENT_HEADER_EXT_TYPE_PEBS_INDEX, EVENT_HEADER_EXT_TYPE_PMC_COUNTERS
			// EVENT_HEADER_EXT_TYPE_PSM_KEY, EVENT_HEADER_EXT_TYPE_EVENT_KEY,
			// EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY, EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL
			// EVENT_HEADER_EXT_TYPE_PROV_TRAITS
		}
	}
	return extendedData
}

// propertyParser is used for parsing properties from raw EVENT_RECORD structure.
type propertyParser struct {
	record        *eventRecordC
	info          *traceEventInfoC
	infoBuffer    []byte
	data          []byte
	ptrSize       uintptr
	ignoreMapInfo bool

	parseBuffer []byte
}

func (p *propertyParser) free() {
	eventInfoBufferPool.Put(p.infoBuffer)
	dataBufferPool.Put(p.parseBuffer)
}

func newPropertyParser(r *eventRecordC, ignoreMapInfo bool) (*propertyParser, error) {
	info, infoBuffer, err := getEventInformation(r)
	if err != nil {
		return nil, fmt.Errorf("failed to get event information; %w", err)
	}
	ptrSize := unsafe.Sizeof(uint64(0))
	if r.EventHeader.Flags&eventHeaderFlag32BitHeader == eventHeaderFlag32BitHeader {
		ptrSize = unsafe.Sizeof(uint32(0))
	}
	return &propertyParser{
		record:        r,
		info:          info,
		infoBuffer:    infoBuffer,
		ptrSize:       ptrSize,
		data:          unsafe.Slice((*uint8)(r.UserData), r.UserDataLength),
		ignoreMapInfo: ignoreMapInfo,
		parseBuffer:   dataBufferPool.Get().([]byte),
	}, nil
}

var eventInfoBufferSize = 10 * 1024

var eventInfoBufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, eventInfoBufferSize)
	},
}

const dataBufferSize = 100

var dataBufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, dataBufferSize)
	},
}

// getEventInformation wraps TdhGetEventInformation. It extracts some kind of
// simplified event information used by Tdh* family of function.
func getEventInformation(pEvent *eventRecordC) (*traceEventInfoC, []byte, error) {
	buffer := eventInfoBufferPool.Get().([]byte)

	var bufferSize = uint32(len(buffer))

	// Retrieve a buffer size.
	err := tdhGetEventInformation(
		pEvent,
		0,
		nil,
		&buffer[0],
		&bufferSize,
	)
	if err == windows.ERROR_INSUFFICIENT_BUFFER {
		buffer = make([]uint8, bufferSize)

		// Fetch the buffer itself.
		err = tdhGetEventInformation(
			pEvent,
			0,
			nil,
			&buffer[0],
			&bufferSize,
		)
	}

	if err != nil {
		return nil, nil, fmt.Errorf("TdhGetEventInformation failed; %w", err)
	}

	return (*traceEventInfoC)(unsafe.Pointer(&buffer[0])), buffer, nil
}

func getPropertyName(info *traceEventInfoC, i int) unsafe.Pointer {
	return unsafe.Add(unsafe.Pointer(info), info.EventPropertyInfoArray[i].NameOffset)
}

// getPropertyName returns a name of the @i-th event property.
func (p *propertyParser) getPropertyName(i int) string {
	return createUTF16String(getPropertyName(p.info, i), anysizeArray)
}

func getLengthFromProperty(event *eventRecordC, dataDescriptor *propertyDataDescriptor) (uint32, error) {
	var length uint32
	err := tdhGetProperty(
		event,
		0,
		nil,
		1,
		dataDescriptor,
		uint32(unsafe.Sizeof(length)),
		unsafe.Pointer(&length),
	)
	if err != nil {
		return 0, err
	}
	return length, nil
}

func (p *propertyParser) getArraySize(propertyInfo eventPropertyInfoC) (uint32, error) {
	if (propertyInfo.Flags & propertyParamCount) == propertyParamCount {
		var dataDescriptor propertyDataDescriptor
		// Use the countPropertyIndex member of the EVENT_PROPERTY_INFO structure
		// to locate the property that contains the size of the array.
		dataDescriptor.PropertyName = getPropertyName(p.info, int(propertyInfo.countPropertyIndex()))
		dataDescriptor.ArrayIndex = 0xFFFFFFFF
		return getLengthFromProperty(p.record, &dataDescriptor)
	} else {
		return uint32(propertyInfo.count()), nil
	}
}

// getPropertyValue retrieves a value of @i-th property.
//
// N.B. getPropertyValue HIGHLY depends not only on @i but also on memory
// offsets, so check twice calling with non-sequential indexes.
func (p *propertyParser) getPropertyValue(i int) (interface{}, error) {
	propertyInfo := p.info.EventPropertyInfoArray[i]

	arraySize, err := p.getArraySize(propertyInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to get array size; %w", err)
	}

	result := make([]interface{}, arraySize)
	for j := 0; j < int(arraySize); j++ {
		var (
			value interface{}
			err   error
		)
		// Note that we pass same idx to parse function. Actual returned values are controlled
		// by data pointers offsets.
		if propertyInfo.Flags&propertyStruct == propertyStruct {
			value, err = p.parseStruct(propertyInfo)
		} else {
			value, err = p.parseSimpleType(propertyInfo)
		}
		if err != nil {
			return nil, err
		}
		result[j] = value
	}
	if ((propertyInfo.Flags & propertyParamCount) == propertyParamCount) ||
		(propertyInfo.count() > 1) {
		return result, nil
	}
	return result[0], nil
}

// parseStruct tries to extract fields of embedded structure at property @i.
func (p *propertyParser) parseStruct(propertyInfo eventPropertyInfoC) (map[string]interface{}, error) {
	startIndex := propertyInfo.structType().StructStartIndex
	lastIndex := startIndex + propertyInfo.structType().NumOfStructMembers

	structure := make(map[string]interface{}, lastIndex-startIndex)
	for j := startIndex; j < lastIndex; j++ {
		name := p.getPropertyName(int(j))
		value, err := p.getPropertyValue(int(j))
		if err != nil {
			return nil, fmt.Errorf("failed parse field %q of complex property type; %w", name, err)
		}
		structure[name] = value
	}
	return structure, nil
}

// parseSimpleType wraps TdhFormatProperty to get rendered to string value of
// @i-th event property.
func (p *propertyParser) parseSimpleType(propertyInfo eventPropertyInfoC) (string, error) {
	var mapInfo unsafe.Pointer
	if !p.ignoreMapInfo {
		var err error
		mapInfo, err = p.getMapInfo(propertyInfo)
		if err != nil {
			return "", fmt.Errorf("failed to get map info; %w", err)
		}
	}

	propertyLength, err := p.getPropertyLength(propertyInfo)
	if err != nil {
		return "", fmt.Errorf("failed to get property length; %w", err)
	}

	inType := propertyInfo.nonStructType.InType
	outType := propertyInfo.nonStructType.OutType

	var userDataConsumed uint16

	// Initialize parse buffer with a size that should be sufficient for most properties.
	formattedDataSize := uint32(len(p.parseBuffer))

retryLoop:
	for {
		var dataPtr *uint8
		if len(p.data) > 0 {
			dataPtr = &p.data[0]
		}
		err := tdhFormatProperty(
			p.record,
			(*uint8)(mapInfo),
			uint32(p.ptrSize),
			inType,
			outType,
			uint16(propertyLength),
			uint16(len(p.data)),
			dataPtr,
			&formattedDataSize,
			&p.parseBuffer[0],
			&userDataConsumed,
		)

		switch err {
		case nil:
			break retryLoop

		case windows.ERROR_INSUFFICIENT_BUFFER:
			p.parseBuffer = make([]byte, formattedDataSize)
			continue

		case windows.ERROR_EVT_INVALID_EVENT_DATA:
			// Can happen if the MapInfo doesn't match the actual data, e.g pure ETW provider
			// works with the outdated WEL manifest. Discarding MapInfo allows us to access
			// at least the non-interpreted data.
			if mapInfo != nil {
				mapInfo = nil
				continue
			}
			fallthrough // Can't fix. Error.

		default:
			return "", fmt.Errorf("TdhFormatProperty failed; %w", err)
		}
	}
	p.data = p.data[userDataConsumed:]

	return createUTF16String(unsafe.Pointer(&p.parseBuffer[0]), int(formattedDataSize)), nil
}

// getMapInfo retrieve the mapping between the @i-th field and the structure it represents.
// If that mapping exists, function extracts it and returns a pointer to the buffer with
// extracted info. If no mapping defined, function can legitimately return `nil, nil`.
func (p *propertyParser) getMapInfo(propertyInfo eventPropertyInfoC) (unsafe.Pointer, error) {
	mapName := (*uint16)(unsafe.Add(unsafe.Pointer(p.info), propertyInfo.nonStructType.MapNameOffset))

	// Query map info if any exists.
	var mapSize uint32
	err := tdhGetEventMapInformation(
		p.record,
		mapName,
		nil,
		&mapSize,
	)
	switch err {
	case windows.ERROR_NOT_FOUND:
		return nil, nil // Pretty ok, just no map info
	case windows.ERROR_INSUFFICIENT_BUFFER:
		// Info exists -- need a buffer.
	default:
		return nil, fmt.Errorf("TdhGetEventMapInformation failed to get size; %w", err)
	}

	// Get the info itself.
	mapInfo := make([]byte, int(mapSize))
	err = tdhGetEventMapInformation(
		p.record,
		mapName,
		&mapInfo[0],
		&mapSize,
	)
	if err != nil {
		return nil, fmt.Errorf("TdhGetEventMapInformation failed; %w", err)
	}

	if len(mapInfo) == 0 {
		return nil, nil
	}
	return unsafe.Pointer(&mapInfo[0]), nil
}

// Creates UTF16 string from raw parts.
//
// Actually in go we have no way to make a slice from raw parts, ref:
// - https://github.com/golang/go/issues/13656
// - https://github.com/golang/go/issues/19367
// So the recommended way is "a fake cast" to the array with maximal len
// with a following slicing.
// Ref: https://github.com/golang/go/wiki/cgo#turning-c-arrays-into-go-slices
func createUTF16String(ptr unsafe.Pointer, length int) string {
	if length == 0 {
		return ""
	}
	chars := (*[anysizeArray]uint16)(ptr)[:length:length]

	// Detect actual length of UTF-16 zero terminated string
	var fastEncode = true
	for i, v := range chars {
		if v == 0 {
			chars = chars[0:i]
			break
		}
		if v >= 0x800 {
			fastEncode = false
		}
	}
	if fastEncode {
		// Optimized variant for simple texts
		var bytes = make([]byte, 0, len(chars)*2)
		for _, v := range chars {
			// Encoding for UTF-8, see https://en.wikipedia.org/wiki/UTF-8#Encoding
			if v < 0x80 {
				bytes = append(bytes, uint8(v))
			} else {
				bytes = append(bytes, 0b11000000&uint8(v>>6), 0b10000000&uint8(v))
			}
		}
		return *(*string)(unsafe.Pointer(&bytes))
	}
	return string(utf16.Decode(chars))
}

// getPropertyLength returns an associated length of the @j-th property of @pInfo.
// If the length is available, retrieve it here. In some cases, the length is 0.
// This can signify that we are dealing with a variable length field such as a structure
// or a string.
func (p *propertyParser) getPropertyLength(propertyInfo eventPropertyInfoC) (uint32, error) {
	// If the property is a binary blob it can point to another property that defines the
	// blob's size. The PropertyParamLength flag tells you where the blob's size is defined.
	if (propertyInfo.Flags & propertyParamLength) == propertyParamLength {
		var dataDescriptor propertyDataDescriptor
		dataDescriptor.PropertyName = getPropertyName(p.info, int(propertyInfo.lengthPropertyIndex()))
		dataDescriptor.ArrayIndex = 0xFFFFFFFF
		return getLengthFromProperty(p.record, &dataDescriptor)
	}

	// If the property is an IP V6 address, you must set the PropertyLength parameter to the size
	// of the IN6_ADDR structure:
	// https://docs.microsoft.com/en-us/windows/win32/api/tdh/nf-tdh-tdhformatproperty#remarks
	inType := propertyInfo.nonStructType.InType
	outType := propertyInfo.nonStructType.OutType
	if TdhIntypeBinary == inType && TdhOuttypeIpv6 == outType {
		return 16, nil
	}

	// If no special cases handled -- just return the length defined if the info.
	// In some cases, the length is 0. This can signify that we are dealing with a variable
	// length field such as a structure or a string.
	return uint32(propertyInfo.length()), nil
}

const (
	TdhIntypeBinary = 14
	TdhOuttypeIpv6  = 24
)

//sys tdhGetEventInformation(event *eventRecordC, contextCount uint32, context unsafe.Pointer, buffer *uint8, bufferSize *uint32) (ret error) = tdh.TdhGetEventInformation
//sys tdhGetPropertySize(event *eventRecordC, contextCount uint32, context unsafe.Pointer, propertyDataCount uint32, propertyData *propertyDataDescriptor, propertySize *uint32) (ret error) = tdh.TdhGetPropertySize
//sys tdhGetProperty(event *eventRecordC, contextCount uint32, context unsafe.Pointer, propertyDataCount uint32, propertyData *propertyDataDescriptor, bufferSize uint32, buffer unsafe.Pointer) (ret error) = tdh.TdhGetProperty
//sys tdhGetEventMapInformation(event *eventRecordC, mapName *uint16, buffer *uint8, bufferSize *uint32) (ret error) = tdh.TdhGetEventMapInformation
//sys tdhFormatProperty(event *eventRecordC, mapInfo *uint8, pointerSize uint32, inType uint16, outType uint16, propertyLength uint16, userDataLength uint16, userData *uint8, bufferSize *uint32, buffer *uint8, userDataConsumed *uint16) (ret error) = tdh.TdhFormatProperty
