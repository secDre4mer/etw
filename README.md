# etw
[![GoDev](https://img.shields.io/static/v1?label=godev&message=reference&color=00add8&style=flat-square)](https://pkg.go.dev/github.com/bi-zone/etw)
[![Go Report Card](https://goreportcard.com/badge/github.com/bi-zone/etw)](https://goreportcard.com/report/github.com/bi-zone/etw)
[![Lint & Test Go code](https://img.shields.io/github/workflow/status/bi-zone/etw/Lint%20&%20Test%20Go%20code?style=flat-square)](https://github.com/bi-zone/etw/actions)


`etw` is a Go-package that allows you to receive [Event Tracing for Windows (ETW)](https://docs.microsoft.com/en-us/windows/win32/etw/about-event-tracing)
events in go code.

`etw` allows you to process events from new 
[TraceLogging](https://docs.microsoft.com/en-us/windows/win32/tracelogging/trace-logging-about) providers
as well as from classic (aka EventLog) providers, so you could actually listen to anything you can
see in Event Viewer window.

## Fork info

This is a fork of https://github.com/bi-zone/etw that adds some functionality, especially:
 - Looking up (manifest) providers at runtime
 - Building without CGO
 - Filtering on ETW sessions
 - Registering for multiple providers in a single ETW session

## Docs
Package reference is available at https://pkg.go.dev/github.com/secDre4mer/etw

Examples are located in [examples](./examples) folder.

## Usage

```go
package main

import (
	"log"
	"os"
	"os/signal"
	"sync"

	"github.com/secDre4mer/etw"
)

func main() {
	session, err := etw.NewSession()
	if err != nil {
		log.Fatalf("Failed to create etw session: %s", err)
	}

	// Subscribe to Microsoft-Windows-DNS-Client
	dnsClient, err := etw.LookupProvider("Microsoft-Windows-DNS-Client")
	if err != nil {
		log.Fatalf("Failed to find DNS client provider: %s", err)
    }
	if err := session.AddProvider(dnsClient.Guid); err != nil {
		log.Fatalf("Failed to register for provider: %v", err)
	}

	// Wait for "DNS query request" events to log outgoing DNS requests.
	cb := func(e *etw.Event) {
		if e.Header.ID != 3006 {
			return
		}
		if data, err := e.EventProperties(); err == nil && data["QueryType"] == "1" {
			log.Printf("PID %d just queried DNS for domain %v", e.Header.ProcessID, data["QueryName"])
		}
	}

	// `session.Process` blocks until `session.Close()`, so start it in routine.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		if err := session.Process(cb); err != nil {
			log.Printf("[ERR] Got error processing events: %s", err)
		}
		wg.Done()
	}()

	// Trap cancellation.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	<-sigCh

	if err := session.Close(); err != nil {
		log.Printf("[ERR] Got error closing the session: %s", err)
	}
	wg.Wait()
}

```

More sophisticated examples can be found in [examples](./examples) folder.

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.