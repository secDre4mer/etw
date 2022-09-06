package etw

import "golang.org/x/sys/windows"

type eventTrace struct {
	eventTraceCommon
}

type eventTraceLogfile struct {
	eventTraceLogfileCommon
}

type eventRecordC struct {
	eventRecordCommon
}

type eventTraceProperties struct {
	eventTracePropertiesCommon
}

type enableTraceParameters struct {
	Version          uint32
	EnableProperty   uint32
	ControlFlags     uint32
	SourceId         windows.GUID
	EnableFilterDesc *eventFilterDescriptorC
	FilterDescCount  uint32
	_                uint32 // Padding
}

type eventFilterDescriptorC struct {
	eventFilterDescriptorCommon
}
