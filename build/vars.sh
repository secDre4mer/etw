#!/usr/bin/env bash

export GOOS=windows
export CGO_ENABLED=0

GOARCH=$(go env GOARCH)