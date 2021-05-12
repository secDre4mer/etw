package etw

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

/*
#include <windows.h>

typedef struct _TRACE_PROVIDER_INFO {
  GUID  ProviderGuid;
  ULONG SchemaSource;
  ULONG ProviderNameOffset;
} TRACE_PROVIDER_INFO;

typedef struct _PROVIDER_ENUMERATION_INFO {
  ULONG               NumberOfProviders;
  ULONG               Reserved;
  TRACE_PROVIDER_INFO TraceProviderInfoArray[ANYSIZE_ARRAY];
} PROVIDER_ENUMERATION_INFO;
 */
import "C"

var (
	enumerateProviders = tdh.NewProc("TdhEnumerateProviders")
	enumerateProviderFieldInformation = tdh.NewProc("TdhEnumerateProviderFieldInformation")
	queryProviderFieldInformation = tdh.NewProc("TdhQueryProviderFieldInformation")
)

type Provider struct {
	Name string
	Guid windows.GUID
}

type ProviderField struct {
	Name string
	Description string
	ID uint64
}

type providerFieldInfoArray struct {
	NumberOfElements uint32
	FieldType uint32
	FieldInfoArray [0]providerFieldInfo
}

type providerFieldInfo struct {
	NameOffset uint32
	DescriptionOffset uint32
	Value uint64
}

type eventFieldType uintptr

const(
	eventKeywordInformation eventFieldType = iota
	eventLevelInformation
	eventChannelInformation
	eventTaskInformation
	eventOpcodeInformation
)

func (p Provider) QueryOpcode(taskValue uint16, opcodeValue uint8) (ProviderField, error) {
	fieldValue := uint64(taskValue) + (uint64(opcodeValue) << 16)
	fieldList, err := p.QueryField(fieldValue, eventOpcodeInformation)
	if err != nil {
		return ProviderField{}, err
	}
	if len(fieldList) == 0 {
		return ProviderField{}, fmt.Errorf("no information returned")
	}
	return fieldList[0], nil
}

func (p Provider) QueryTask(taskValue uint16) (ProviderField, error) {
	fieldList, err := p.QueryField(uint64(taskValue), eventTaskInformation)
	if err != nil {
		return ProviderField{}, err
	}
	if len(fieldList) == 0 {
		return ProviderField{}, fmt.Errorf("no information returned")
	}
	return fieldList[0], nil
}

func (p Provider) QueryField(fieldValue uint64, fieldType eventFieldType) ([]ProviderField, error) {
	var requiredSize int32
	status, _, _ := queryProviderFieldInformation.Call(
		uintptr(unsafe.Pointer(&p.Guid)),
		uintptr(fieldValue),
		uintptr(fieldType),
		0,
		uintptr(unsafe.Pointer(&requiredSize)),
	)
	if status != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
		return nil, windows.Errno(status)
	}
	if requiredSize == 0 {
		return nil, nil
	}
	var buffer = make([]byte, requiredSize)
	status, _, _ = queryProviderFieldInformation.Call(
		uintptr(unsafe.Pointer(&p.Guid)),
		uintptr(fieldValue),
		uintptr(fieldType),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&requiredSize)),
	)
	if status != uintptr(windows.ERROR_SUCCESS) {
		return nil, windows.Errno(status)
	}
	return parseFieldInfoArray(buffer), nil
}

func (p Provider) ListKeywords() ([]ProviderField, error) {
	return p.listFields(eventKeywordInformation)
}

func (p Provider) ListLevels() ([]ProviderField, error) {
	return p.listFields(eventLevelInformation)
}

func (p Provider) ListChannels() ([]ProviderField, error) {
	return p.listFields(eventChannelInformation)
}

func (p Provider) listFields(fieldType eventFieldType) ([]ProviderField, error) {
	var requiredSize int32
	status, _, _ := enumerateProviderFieldInformation.Call(
		uintptr(unsafe.Pointer(&p.Guid)),
		uintptr(fieldType),
		0,
		uintptr(unsafe.Pointer(&requiredSize)),
	)
	if status != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
		return nil, windows.Errno(status)
	}
	if requiredSize == 0 {
		return nil, nil
	}
	var buffer = make([]byte, requiredSize)
	status, _, _ = enumerateProviderFieldInformation.Call(
		uintptr(unsafe.Pointer(&p.Guid)),
		uintptr(fieldType),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&requiredSize)),
	)
	if status != uintptr(windows.ERROR_SUCCESS) {
		return nil, windows.Errno(status)
	}
	return parseFieldInfoArray(buffer), nil
}

func parseFieldInfoArray(buffer []byte) []ProviderField {
	infoArray := (*providerFieldInfoArray)(unsafe.Pointer(&buffer[0]))
	// Recast field info array to escape golang boundary checks
	fieldInfoArray := (*[1 << 27]providerFieldInfo)(unsafe.Pointer(&infoArray.FieldInfoArray))
	var fields []ProviderField
	for _, fieldInfo := range fieldInfoArray[:infoArray.NumberOfElements] {
		fields = append(fields, ProviderField{
			Name:        parseUnicodeStringAtOffset(buffer, int(fieldInfo.NameOffset)),
			Description: parseUnicodeStringAtOffset(buffer, int(fieldInfo.DescriptionOffset)),
			ID:          fieldInfo.Value,
		})
	}
	return fields
}

func LookupProvider(name string) (Provider, error) {
	providers, err := ListProviders()
	if err != nil {
		return Provider{}, err
	}
	for _, provider := range providers {
		if provider.Name == name {
			return provider, nil
		}
	}
	return Provider{}, fmt.Errorf("provider not found")
}

func ListProviders() ([]Provider, error) {
	var requiredSize uintptr
	enumerateProviders.Call(0, uintptr(unsafe.Pointer(&requiredSize)))
	status := windows.ERROR_INSUFFICIENT_BUFFER
	var buffer []byte
	for status == windows.ERROR_INSUFFICIENT_BUFFER {
		buffer = make([]byte, requiredSize)
		plainStatus, _, _ := enumerateProviders.Call(
			uintptr(unsafe.Pointer(&buffer[0])),
			uintptr(unsafe.Pointer(&requiredSize)))
		status = windows.Errno(plainStatus)
	}
	if status != windows.ERROR_SUCCESS {
		return nil, status
	}
	var parsedProviders []Provider
	enumerationInfo := (*C.PROVIDER_ENUMERATION_INFO)(unsafe.Pointer(&buffer[0]))
	// Recast provider info array to escape golang boundary checks
	providerInfoArray := (*[1 << 27]C.TRACE_PROVIDER_INFO)(unsafe.Pointer(&enumerationInfo.TraceProviderInfoArray))
	for _, providerInfo := range providerInfoArray[:enumerationInfo.NumberOfProviders] {
		parsedProviders = append(parsedProviders, Provider{
			Name: parseUnicodeStringAtOffset(buffer, int(providerInfo.ProviderNameOffset)),
			Guid: windowsGUIDToGo(providerInfo.ProviderGuid),
		})
	}
	return parsedProviders, nil
}

func parseUnicodeStringAtOffset(buffer []byte, offset int) string {
	var nameArray []uint16
	for j := offset; j < len(buffer) - 1; j+=2 {
		unicodeChar := binary.LittleEndian.Uint16(buffer[j:])
		if unicodeChar == 0 {
			break
		}
		nameArray = append(nameArray, unicodeChar)
	}
	return string(utf16.Decode(nameArray))
}
