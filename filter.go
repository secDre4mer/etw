package etw

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

type EventFilter interface {
	EventFilterDescriptor() (EventFilterDescriptor, error)
	Type() EventFilterType
	Merge(filter EventFilter) (EventFilter, error)
}

type EventFilterType uint32

const (
	EVENT_FILTER_TYPE_SCHEMATIZED EventFilterType = 0x80000000
	EVENT_FILTER_TYPE_EVENT_ID    EventFilterType = 0x80000200
	EVENT_FILTER_TYPE_PAYLOAD     EventFilterType = 0x80000100
)

// EventIdFilter is a simple filter that filters by Event ID.
// Either a positive filter can be defined that allows only specific Event IDs or a negative filter that disallows
// specific Event IDs. Specifying both types is not allowed.
type EventIdFilter struct {
	// The Event IDs that the filter should look for
	EventIds []uint16
	// True for a filter that accepts only the given Event IDs, False for a filter that rejects the given Event IDs
	PositiveFilter bool
}

// EVENT_FILTER_EVENT_ID for Go since it's not defined in MinGW headers
type eventFilterEventId struct {
	FilterIn bool
	_        byte
	Count    uint16
	// ... Events...
}

func (e EventIdFilter) EventFilterDescriptor() (EventFilterDescriptor, error) {
	// Generate a EVENT_FILTER_EVENT_ID structure, as described here:
	// https://docs.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_filter_event_id
	var buffer = make([]byte, int(unsafe.Sizeof(eventFilterEventId{}))+2*len(e.EventIds))
	eventFilter := (*eventFilterEventId)(unsafe.Pointer(&buffer[0]))
	eventFilter.FilterIn = e.PositiveFilter
	eventFilter.Count = uint16(len(e.EventIds))
	for i, eventId := range e.EventIds {
		binary.LittleEndian.PutUint16(buffer[int(unsafe.Sizeof(eventFilterEventId{}))+2*i:], eventId)
	}
	var cDescriptor eventFilterDescriptorC
	cDescriptor.Ptr = unsafe.Pointer(&buffer[0])
	cDescriptor.Size = uint32(len(buffer))
	cDescriptor.Type = uint32(EVENT_FILTER_TYPE_EVENT_ID)
	return EventFilterDescriptor{
		Descriptor: cDescriptor,
		Close: func() error {
			return nil
		},
	}, nil
}

func (e EventIdFilter) Type() EventFilterType {
	return EVENT_FILTER_TYPE_EVENT_ID
}

func (e EventIdFilter) Merge(other EventFilter) (EventFilter, error) {
	otherIdFilter := other.(EventIdFilter)
	if otherIdFilter.PositiveFilter != e.PositiveFilter {
		return nil, errors.New("can't use positive and negative Event ID filters together")
	}
	return EventIdFilter{
		EventIds:       append(e.EventIds, otherIdFilter.EventIds...),
		PositiveFilter: e.PositiveFilter,
	}, nil
}

type EventPayloadFilter struct {
	FilteredProvider   windows.GUID
	FilteredDescriptor EventDescriptor
	Comparisons        []EventPayloadCompare
	AnyMatches         bool
}

// PAYLOAD_FILTER_PREDICATE definition, https://docs.microsoft.com/en-us/windows/win32/api/tdh/ns-tdh-payload_filter_predicate
type payloadFilterPredicate struct {
	FieldName *uint16
	Operation CompareOperation
	Value     *uint16
}

var (
	tdhCreatePayloadFilter                 = tdh.NewProc("TdhCreatePayloadFilter")
	tdhDeletePayloadFilter                 = tdh.NewProc("TdhDeletePayloadFilter")
	tdhAggregatePayloadFilters             = tdh.NewProc("TdhAggregatePayloadFilters")
	tdhCleanupPayloadEventFilterDescriptor = tdh.NewProc("TdhCleanupPayloadEventFilterDescriptor")
)

type EventFilterDescriptor struct {
	Descriptor eventFilterDescriptorC
	Close      func() error
}

func (e EventPayloadFilter) EventFilterDescriptor() (EventFilterDescriptor, error) {
	var anyMatches uintptr
	if e.AnyMatches {
		anyMatches = 1
	}
	var comparisons = make([]payloadFilterPredicate, len(e.Comparisons))
	for i := range e.Comparisons {
		var err error
		comparisons[i], err = e.Comparisons[i].toPayloadFilterPredicate()
		if err != nil {
			return EventFilterDescriptor{}, err
		}
	}
	var payloadFilter uintptr
	status, _, _ := tdhCreatePayloadFilter.Call(
		uintptr(unsafe.Pointer(&e.FilteredProvider)),
		uintptr(unsafe.Pointer(&e.FilteredDescriptor)),
		anyMatches,
		uintptr(len(comparisons)),
		uintptr(unsafe.Pointer(&comparisons[0])),
		uintptr(unsafe.Pointer(&payloadFilter)),
	)
	if status != 0 {
		return EventFilterDescriptor{}, fmt.Errorf("TdhCreatePayloadFilter failed with %w", windows.Errno(status))
	}
	defer tdhDeletePayloadFilter.Call(uintptr(unsafe.Pointer(&payloadFilter)))
	var filterDescriptor eventFilterDescriptorC
	status, _, _ = tdhAggregatePayloadFilters.Call(
		1,
		uintptr(unsafe.Pointer(&payloadFilter)),
		0,
		uintptr(unsafe.Pointer(&filterDescriptor)),
	)
	if status != 0 {
		return EventFilterDescriptor{}, fmt.Errorf("TdhAggregatePayloadFilters failed with %w", windows.Errno(status))
	}
	cleanup := func() error {
		status, _, _ := tdhCleanupPayloadEventFilterDescriptor.Call(uintptr(unsafe.Pointer(&filterDescriptor)))
		if status != 0 {
			return fmt.Errorf("TdhCleanupPayloadEventFilterDescriptor failed with %w", windows.Errno(status))
		}
		return nil
	}
	return EventFilterDescriptor{
		Descriptor: filterDescriptor,
		Close:      cleanup,
	}, nil
}

func (EventPayloadFilter) Type() EventFilterType {
	return EVENT_FILTER_TYPE_PAYLOAD
}

func (EventPayloadFilter) Merge(filter EventFilter) (EventFilter, error) {
	return nil, errors.New("payload filter merge not supported yet")
}

type EventPayloadCompare struct {
	Field     string
	Value     string
	Operation CompareOperation
}

func (e EventPayloadCompare) toPayloadFilterPredicate() (payloadFilterPredicate, error) {
	fieldName, err := windows.UTF16PtrFromString(e.Field)
	if err != nil {
		return payloadFilterPredicate{}, err
	}
	value, err := windows.UTF16PtrFromString(e.Value)
	if err != nil {
		return payloadFilterPredicate{}, err
	}
	return payloadFilterPredicate{
		FieldName: fieldName,
		Operation: e.Operation,
		Value:     value,
	}, nil
}

type CompareOperation uint16

const (
	CompareIntegerEqual CompareOperation = iota
	CompareIntegerNotEqual
	CompareIntegerLessOrEqual
	CompareIntegerGreater
	CompareIntegerLess
	CompareIntegerGreatorOrEqual
	CompareIntegerBetween
	CompareIntegerNotBetween
	CompareIntegerModulo
)
const (
	CompareStringContains    CompareOperation = 20
	CompareStringNotContains CompareOperation = 21
	CompareStringEquals      CompareOperation = 30
	CompareStringNotEquals   CompareOperation = 31
)
