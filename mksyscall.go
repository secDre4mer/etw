//go:build generate
// +build generate

package etw

//go:generate go run golang.org/x/sys/windows/mkwinsyscall -output zsyscall.go event.go session.go provider.go filter.go
