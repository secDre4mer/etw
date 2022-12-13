package etw

import (
	"golang.org/x/sys/windows"
)

var (
	advapi32       = windows.NewLazySystemDLL("advapi32.dll")
	procOpenTraceW = advapi32.NewProc("OpenTraceW")
	procCloseTrace = advapi32.NewProc("CloseTrace")
)
