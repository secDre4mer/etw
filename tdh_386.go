package etw

import "golang.org/x/sys/windows"

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
	eventFilterDescriptorCommon
	_ uint32 // Padding
}
