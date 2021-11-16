package etw

import "golang.org/x/sys/windows"

type windowsVersion int

const (
	unsupportedOldVersion windowsVersion = iota
	windowsVista
	windows7
	windows8
	windows10OrNewer
)

func getWindowsVersion() windowsVersion {
	osVersion := windows.RtlGetVersion()
	major, minor := osVersion.MajorVersion, osVersion.MinorVersion
	// See https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-osversioninfoexa#remarks for version info
	switch {
	case major > 6:
		return windows10OrNewer
	case major == 6 && minor >= 2:
		return windows8
	case major == 6 && minor == 1:
		return windows7
	case major == 6 && minor == 0:
		return windowsVista
	default:
		return unsupportedOldVersion
	}
}
