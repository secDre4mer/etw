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
	eventFilterTypeSchematized EventFilterType = 0x80000000
	eventFilterTypeEventId     EventFilterType = 0x80000200
	eventFilterTypePayload     EventFilterType = 0x80000100
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
	cDescriptor.Type = uint32(eventFilterTypeEventId)
	return EventFilterDescriptor{
		Descriptor: cDescriptor,
		Close: func() error {
			return nil
		},
	}, nil
}

func (e EventIdFilter) Type() EventFilterType {
	return eventFilterTypeEventId
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

type EventFilterDescriptor struct {
	Descriptor eventFilterDescriptorC
	Close      func() error
}

func (e EventPayloadFilter) EventFilterDescriptor() (EventFilterDescriptor, error) {
	var comparisons = make([]payloadFilterPredicate, len(e.Comparisons))
	for i := range e.Comparisons {
		var err error
		comparisons[i], err = e.Comparisons[i].toPayloadFilterPredicate()
		if err != nil {
			return EventFilterDescriptor{}, err
		}
	}
	var payloadFilter uintptr
	err := createPayloadFilter(
		&e.FilteredProvider,
		&e.FilteredDescriptor,
		e.AnyMatches,
		uint32(len(comparisons)),
		&comparisons[0],
		&payloadFilter,
	)
	if err != nil {
		return EventFilterDescriptor{}, fmt.Errorf("TdhCreatePayloadFilter failed with %w", err)
	}
	defer deletePayloadFilter(&payloadFilter)
	var filterDescriptor eventFilterDescriptorC
	err = aggregatePayloadFilters(
		1,
		&payloadFilter,
		nil,
		&filterDescriptor,
	)
	if err != nil {
		return EventFilterDescriptor{}, fmt.Errorf("TdhAggregatePayloadFilters failed with %w", err)
	}
	cleanup := func() error {
		err := cleanupPayloadEventFilterDescriptor(&filterDescriptor)
		if err != nil {
			return fmt.Errorf("TdhCleanupPayloadEventFilterDescriptor failed with %w", err)
		}
		return nil
	}
	return EventFilterDescriptor{
		Descriptor: filterDescriptor,
		Close:      cleanup,
	}, nil
}

func (EventPayloadFilter) Type() EventFilterType {
	return eventFilterTypePayload
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

//sys createPayloadFilter(providerGuid *windows.GUID, descriptor *EventDescriptor, eventMatchAny bool, payloadPredicateCount uint32, payloadPredicates *payloadFilterPredicate, payloadFilter *uintptr) (ret error) = tdh.TdhCreatePayloadFilter
//sys deletePayloadFilter(payloadFilter *uintptr) (ret error) = tdh.TdhDeletePayloadFilter
//sys aggregatePayloadFilters(payloadFilterCount uint32, payloadFilters *uintptr, eventMatchAllFlags *bool, filterDescriptor *eventFilterDescriptorC) (ret error) = tdh.TdhAggregatePayloadFilters
//sys cleanupPayloadEventFilterDescriptor(filterDescriptor *eventFilterDescriptorC) (ret error) = tdh.TdhCleanupPayloadEventFilterDescriptor
