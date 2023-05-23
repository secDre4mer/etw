package etw

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

type eventTrace struct {
	eventTraceCommon
	_ uint32 // Padding
}

type eventTraceLogfile struct {
	eventTraceLogfileCommon
	_ uint32 // Padding
}

type eventRecordC struct {
	eventRecordCommon
	_ uint32 // Padding
}

type eventTraceProperties struct {
	eventTracePropertiesCommon
	_ uint32 // Padding
}

type enableTraceParameters struct {
	Version          uint32
	EnableProperty   uint32
	ControlFlags     uint32
	SourceId         windows.GUID
	EnableFilterDesc *eventFilterDescriptorC
	FilterDescCount  uint32
}

type eventFilterDescriptorC struct {
	// Ptr is a ULONGLONG, meaning a 64 bit value, even for 32 bit.
	// Since a pointer is a 32 bit value, the higher bytes are always zero, so in little endian it's a 32 bit pointer followed by 4 zero bytes.
	Ptr  unsafe.Pointer
	_    uint32
	Size uint32
	Type uint32
}
