package etw

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

type Provider struct {
	Name string
	Guid windows.GUID
}

type ProviderField struct {
	Name        string
	Description string
	ID          uint64
}

type EventFieldType uint32

const (
	EventKeywordInformation EventFieldType = iota
	EventLevelInformation
	EventChannelInformation
	EventTaskInformation
	EventOpcodeInformation
)

func (p Provider) QueryOpcode(taskValue uint16, opcodeValue uint8) (ProviderField, error) {
	fieldValue := uint64(taskValue) + (uint64(opcodeValue) << 16)
	fieldList, err := p.QueryField(fieldValue, EventOpcodeInformation)
	if err != nil {
		return ProviderField{}, err
	}
	if len(fieldList) == 0 {
		return ProviderField{}, fmt.Errorf("no information returned")
	}
	return fieldList[0], nil
}

func (p Provider) QueryTask(taskValue uint16) (ProviderField, error) {
	fieldList, err := p.QueryField(uint64(taskValue), EventTaskInformation)
	if err != nil {
		return ProviderField{}, err
	}
	if len(fieldList) == 0 {
		return ProviderField{}, fmt.Errorf("no information returned")
	}
	return fieldList[0], nil
}

func (p Provider) QueryField(fieldValue uint64, fieldType EventFieldType) ([]ProviderField, error) {
	var requiredSize uint32
	err := queryProviderFieldInformation(
		&p.Guid,
		fieldValue,
		fieldType,
		nil,
		&requiredSize,
	)
	if err != windows.ERROR_INSUFFICIENT_BUFFER {
		return nil, err
	}
	if requiredSize == 0 {
		return nil, nil
	}
	var buffer = make([]byte, requiredSize)
	err = queryProviderFieldInformation(
		&p.Guid,
		fieldValue,
		fieldType,
		(*providerFieldInfoArray)(unsafe.Pointer(&buffer[0])),
		&requiredSize,
	)
	if err != nil {
		return nil, err
	}
	return parseFieldInfoArray(buffer), nil
}

func (p Provider) ListKeywords() ([]ProviderField, error) {
	return p.listFields(EventKeywordInformation)
}

func (p Provider) ListLevels() ([]ProviderField, error) {
	return p.listFields(EventLevelInformation)
}

func (p Provider) ListChannels() ([]ProviderField, error) {
	return p.listFields(EventChannelInformation)
}

func (p Provider) listFields(fieldType EventFieldType) ([]ProviderField, error) {
	var requiredSize uint32
	err := enumerateProviderFieldInformation(
		&p.Guid,
		fieldType,
		nil,
		&requiredSize,
	)
	if err != windows.ERROR_INSUFFICIENT_BUFFER {
		return nil, err
	}
	if requiredSize == 0 {
		return nil, nil
	}
	var buffer = make([]byte, requiredSize)
	err = enumerateProviderFieldInformation(
		&p.Guid,
		fieldType,
		(*providerFieldInfoArray)(unsafe.Pointer(&buffer[0])),
		&requiredSize,
	)
	if err != nil {
		return nil, err
	}
	return parseFieldInfoArray(buffer), nil
}

func parseFieldInfoArray(buffer []byte) []ProviderField {
	infoArray := (*providerFieldInfoArray)(unsafe.Pointer(&buffer[0]))
	// Recast field info array to escape golang boundary checks
	var fields []ProviderField
	for _, fieldInfo := range infoArray.FieldInfoArray[:infoArray.NumberOfElements] {
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
	var requiredSize uint32
	_ = enumerateProviders(nil, &requiredSize)
	var err error = windows.ERROR_INSUFFICIENT_BUFFER
	var buffer []byte
	for err == windows.ERROR_INSUFFICIENT_BUFFER {
		if requiredSize == 0 {
			return nil, nil
		}
		buffer = make([]byte, requiredSize)
		err = enumerateProviders(
			(*providerEnumerationInfo)(unsafe.Pointer(&buffer[0])),
			&requiredSize,
		)
	}
	if err != nil {
		return nil, err
	}
	var parsedProviders []Provider
	enumerationInfo := (*providerEnumerationInfo)(unsafe.Pointer(&buffer[0]))
	for _, providerInfo := range enumerationInfo.TraceProviderInfoArray[:enumerationInfo.NumberOfProviders] {
		parsedProviders = append(parsedProviders, Provider{
			Name: parseUnicodeStringAtOffset(buffer, int(providerInfo.ProviderNameOffset)),
			Guid: providerInfo.ProviderGuid,
		})
	}
	return parsedProviders, nil
}

func parseUnicodeStringAtOffset(buffer []byte, offset int) string {
	var nameArray []uint16
	for j := offset; j < len(buffer)-1; j += 2 {
		unicodeChar := binary.LittleEndian.Uint16(buffer[j:])
		if unicodeChar == 0 {
			break
		}
		nameArray = append(nameArray, unicodeChar)
	}
	return string(utf16.Decode(nameArray))
}

func (p Provider) ListEvents() ([]EventDescriptor, error) {
	var requiredBufferSize uint32
	err := enumerateManifestProviderEvents(
		&p.Guid,
		nil,
		&requiredBufferSize,
	)
	if err != windows.ERROR_INSUFFICIENT_BUFFER {
		return nil, fmt.Errorf("could not get buffer size for events: %w", err)
	}
	var buffer = make([]byte, requiredBufferSize)
	err = enumerateManifestProviderEvents(&p.Guid, (*providerEventInfo)(unsafe.Pointer(&buffer[0])), &requiredBufferSize)
	if err != windows.ERROR_SUCCESS {
		return nil, fmt.Errorf("could not list events: %w", err)
	}
	eventInfo := (*providerEventInfo)(unsafe.Pointer(&buffer[0]))
	var descriptors = make([]EventDescriptor, eventInfo.NumberOfEvents)
	copy(descriptors, eventInfo.descriptors[:eventInfo.NumberOfEvents])
	return descriptors, nil
}
