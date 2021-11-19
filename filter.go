package etw

import (
	"encoding/binary"
	"errors"
	"unsafe"
)

type EventFilter interface {
	EventFilterDescriptorData() []byte
	Type() eventFilterType
	Merge(filter EventFilter) (EventFilter, error)
}

type eventFilterType uint32

const (
	EVENT_FILTER_TYPE_SCHEMATIZED eventFilterType = 0x80000000
	EVENT_FILTER_TYPE_EVENT_ID    eventFilterType = 0x80000200
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

func (e EventIdFilter) EventFilterDescriptorData() []byte {
	// Generate a EVENT_FILTER_EVENT_ID structure, as described here:
	// https://docs.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_filter_event_id
	var buffer = make([]byte, int(unsafe.Sizeof(eventFilterEventId{}))+2*len(e.EventIds))
	eventFilter := (*eventFilterEventId)(unsafe.Pointer(&buffer[0]))
	eventFilter.FilterIn = e.PositiveFilter
	eventFilter.Count = uint16(len(e.EventIds))
	for i, eventId := range e.EventIds {
		binary.LittleEndian.PutUint16(buffer[int(unsafe.Sizeof(eventFilterEventId{}))+2*i:], eventId)
	}
	return buffer
}

func (e EventIdFilter) Type() eventFilterType {
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
