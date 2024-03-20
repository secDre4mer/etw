package etw

import (
	"fmt"

	"golang.org/x/sys/windows"
)

func ReadEtlFile(path string, callback EventCallback, options ...SessionOption) error {
	utf16Path, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	var config SessionOptions
	for _, opt := range options {
		opt(&config)
	}
	var session = &Session{
		callback: callback,
		config:   config,
	}
	callbackKey := newCallbackKey(session)
	defer freeCallbackKey(callbackKey)

	var logFile eventTraceLogfile
	logFile.LogFileName = utf16Path
	logFile.ProcessTraceMode = processTraceModeEventRecord
	logFile.EventCallback = handleEventStdcall
	logFile.Context = callbackKey

	traceHandle, err := openTrace(&logFile)
	if err != nil {
		return fmt.Errorf("OpenTraceW failed; %w", err)
	}
	defer closeTrace(traceHandle)

	err = processTrace(&traceHandle, 1, nil, nil)
	if err != nil {
		return fmt.Errorf("ProcessTrace failed; %w", err)
	}
	return nil
}
