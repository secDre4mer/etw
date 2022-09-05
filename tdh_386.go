package etw

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
