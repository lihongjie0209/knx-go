package knxsecure

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const maxKeyringBytes = 16 << 20

type Keyring struct {
	CreatedBy  string
	Created    string
	Interfaces map[string]KeyringInterface
	GroupKeys  map[string][]byte
	Backbones  []KeyringBackbone
	Devices    map[string]KeyringDevice
}

type KeyringInterface struct {
	Type, IndividualAddress, Host, Password, Authentication string
	UserID                                                  uint8
	Groups                                                  map[string][]string
}

type KeyringBackbone struct {
	MulticastAddress string
	Latency          uint16
	Key              []byte
}

type KeyringDevice struct {
	IndividualAddress, ManagementPassword, Authentication, SerialNumber string
	ToolKey                                                             []byte
	SequenceNumber                                                      uint64
}

type keyringXML struct {
	XMLName        xml.Name                `xml:"Keyring"`
	CreatedBy      string                  `xml:"CreatedBy,attr"`
	Created        string                  `xml:"Created,attr"`
	Interfaces     []keyringInterfaceXML   `xml:"Interface"`
	Backbones      []keyringBackboneXML    `xml:"Backbone"`
	GroupAddresses keyringGroupCollection  `xml:"GroupAddresses"`
	Devices        keyringDeviceCollection `xml:"Devices"`
}

type keyringInterfaceXML struct {
	Type              string            `xml:"Type,attr"`
	IndividualAddress string            `xml:"IndividualAddress,attr"`
	Host              string            `xml:"Host,attr"`
	UserID            string            `xml:"UserID,attr"`
	Password          string            `xml:"Password,attr"`
	Authentication    string            `xml:"Authentication,attr"`
	Groups            []keyringGroupXML `xml:"Group"`
}

type keyringBackboneXML struct {
	Key              string `xml:"Key,attr"`
	Latency          string `xml:"Latency,attr"`
	MulticastAddress string `xml:"MulticastAddress,attr"`
}

type keyringGroupCollection struct {
	Groups []keyringGroupXML `xml:"Group"`
}
type keyringGroupXML struct {
	Address string `xml:"Address,attr"`
	Key     string `xml:"Key,attr"`
	Senders string `xml:"Senders,attr"`
}
type keyringDeviceCollection struct {
	Devices []keyringDeviceXML `xml:"Device"`
}
type keyringDeviceXML struct {
	IndividualAddress  string `xml:"IndividualAddress,attr"`
	ToolKey            string `xml:"ToolKey,attr"`
	ManagementPassword string `xml:"ManagementPassword,attr"`
	Authentication     string `xml:"Authentication,attr"`
	SequenceNumber     string `xml:"SequenceNumber,attr"`
	SerialNumber       string `xml:"SerialNumber,attr"`
}

func LoadKeyring(data []byte, password string) (*Keyring, error) {
	if len(data) == 0 || len(data) > maxKeyringBytes {
		return nil, errors.New("KNX keyring must contain 1 byte through 16 MiB")
	}
	xmlData, err := keyringXMLBytes(data)
	if err != nil {
		return nil, err
	}
	decoder := xml.NewDecoder(bytes.NewReader(xmlData))
	decoder.Strict = true
	var raw keyringXML
	if err := decoder.Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode KNX keyring XML: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("KNX keyring XML contains trailing content")
	}
	if raw.XMLName.Local != "Keyring" || raw.Created == "" {
		return nil, errors.New("KNX keyring root and Created attribute are required")
	}
	key, err := DeriveKeyringKey(password)
	if err != nil {
		return nil, err
	}
	createdHash := sha256.Sum256([]byte(raw.Created))
	iv := createdHash[:AESKeySize]
	result := &Keyring{CreatedBy: raw.CreatedBy, Created: raw.Created, Interfaces: make(map[string]KeyringInterface), GroupKeys: make(map[string][]byte), Devices: make(map[string]KeyringDevice)}
	for index, item := range raw.Interfaces {
		if err := validateIndividualAddress(item.IndividualAddress); err != nil {
			return nil, fmt.Errorf("KNX keyring interface %d: %w", index, err)
		}
		if _, duplicate := result.Interfaces[item.IndividualAddress]; duplicate {
			return nil, fmt.Errorf("duplicate KNX keyring interface %q", item.IndividualAddress)
		}
		userID, err := parseBoundedUint(item.UserID, 127)
		if err != nil {
			return nil, fmt.Errorf("KNX keyring interface %q user ID: %w", item.IndividualAddress, err)
		}
		iface := KeyringInterface{Type: item.Type, IndividualAddress: item.IndividualAddress, Host: item.Host, UserID: uint8(userID), Groups: make(map[string][]string)}
		if item.Host != "" {
			if err := validateIndividualAddress(item.Host); err != nil {
				return nil, fmt.Errorf("KNX keyring interface %q host: %w", item.IndividualAddress, err)
			}
		}
		if item.Password != "" {
			iface.Password, err = decryptKeyringPassword(item.Password, key, iv)
			if err != nil {
				return nil, fmt.Errorf("KNX keyring interface %q password: %w", item.IndividualAddress, err)
			}
		}
		if item.Authentication != "" {
			iface.Authentication, err = decryptKeyringPassword(item.Authentication, key, iv)
			if err != nil {
				return nil, fmt.Errorf("KNX keyring interface %q authentication: %w", item.IndividualAddress, err)
			}
		}
		for _, group := range item.Groups {
			address, err := canonicalGroupAddress(group.Address)
			if err != nil {
				return nil, fmt.Errorf("KNX keyring interface %q group: %w", item.IndividualAddress, err)
			}
			if _, duplicate := iface.Groups[address]; duplicate {
				return nil, fmt.Errorf("KNX keyring interface %q has duplicate group %q", item.IndividualAddress, address)
			}
			for _, sender := range strings.Fields(group.Senders) {
				if err := validateIndividualAddress(sender); err != nil {
					return nil, fmt.Errorf("KNX keyring group %q sender: %w", address, err)
				}
				iface.Groups[address] = append(iface.Groups[address], sender)
			}
		}
		result.Interfaces[item.IndividualAddress] = iface
	}
	for _, item := range raw.GroupAddresses.Groups {
		address, err := canonicalGroupAddress(item.Address)
		if err != nil {
			return nil, err
		}
		if _, duplicate := result.GroupKeys[address]; duplicate {
			return nil, fmt.Errorf("duplicate KNX keyring group key %q", address)
		}
		result.GroupKeys[address], err = decryptKeyringAESKey(item.Key, key, iv)
		if err != nil {
			return nil, fmt.Errorf("KNX keyring group %q key: %w", address, err)
		}
	}
	for index, item := range raw.Backbones {
		address, err := netip.ParseAddr(item.MulticastAddress)
		if err != nil || !address.Is4() || !address.IsMulticast() {
			return nil, fmt.Errorf("KNX keyring backbone %d multicast address is invalid", index)
		}
		latency, err := parseBoundedUint(item.Latency, 65535)
		if err != nil {
			return nil, fmt.Errorf("KNX keyring backbone %d latency: %w", index, err)
		}
		decrypted, err := decryptKeyringAESKey(item.Key, key, iv)
		if err != nil {
			return nil, fmt.Errorf("KNX keyring backbone %d key: %w", index, err)
		}
		result.Backbones = append(result.Backbones, KeyringBackbone{MulticastAddress: address.String(), Latency: uint16(latency), Key: decrypted})
	}
	for index, item := range raw.Devices.Devices {
		if err := validateIndividualAddress(item.IndividualAddress); err != nil {
			return nil, fmt.Errorf("KNX keyring device %d: %w", index, err)
		}
		if _, duplicate := result.Devices[item.IndividualAddress]; duplicate {
			return nil, fmt.Errorf("duplicate KNX keyring device %q", item.IndividualAddress)
		}
		sequence, err := parseBoundedUint(item.SequenceNumber, 1<<48-1)
		if err != nil {
			return nil, fmt.Errorf("KNX keyring device %q sequence: %w", item.IndividualAddress, err)
		}
		device := KeyringDevice{IndividualAddress: item.IndividualAddress, SequenceNumber: sequence, SerialNumber: item.SerialNumber}
		if item.ToolKey != "" {
			device.ToolKey, err = decryptKeyringAESKey(item.ToolKey, key, iv)
			if err != nil {
				return nil, fmt.Errorf("KNX keyring device %q tool key: %w", item.IndividualAddress, err)
			}
		}
		if item.ManagementPassword != "" {
			device.ManagementPassword, err = decryptKeyringPassword(item.ManagementPassword, key, iv)
			if err != nil {
				return nil, fmt.Errorf("KNX keyring device %q management password: %w", item.IndividualAddress, err)
			}
		}
		if item.Authentication != "" {
			device.Authentication, err = decryptKeyringPassword(item.Authentication, key, iv)
			if err != nil {
				return nil, fmt.Errorf("KNX keyring device %q authentication: %w", item.IndividualAddress, err)
			}
		}
		result.Devices[item.IndividualAddress] = device
	}
	return result, nil
}

func keyringXMLBytes(data []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(data)
	if bytes.HasPrefix(trimmed, []byte("<")) {
		return append([]byte(nil), trimmed...), nil
	}
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, errors.New("KNX keyring is neither XML nor a valid ZIP archive")
	}
	var content []byte
	for _, file := range reader.File {
		if file.FileInfo().IsDir() {
			continue
		}
		if content != nil {
			return nil, errors.New("KNX keyring ZIP must contain exactly one file")
		}
		if file.UncompressedSize64 > maxKeyringBytes {
			return nil, errors.New("KNX keyring ZIP entry exceeds 16 MiB")
		}
		opened, err := file.Open()
		if err != nil {
			return nil, err
		}
		content, err = io.ReadAll(io.LimitReader(opened, maxKeyringBytes+1))
		closeErr := opened.Close()
		if err != nil {
			return nil, err
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if len(content) > maxKeyringBytes {
			return nil, errors.New("KNX keyring ZIP entry exceeds 16 MiB")
		}
	}
	if len(content) == 0 {
		return nil, errors.New("KNX keyring ZIP contains no data file")
	}
	return content, nil
}

func decryptKeyringAESKey(encoded string, key, iv []byte) ([]byte, error) {
	decrypted, err := decryptKeyringValue(encoded, key, iv)
	if err != nil {
		return nil, err
	}
	if len(decrypted) != AESKeySize {
		return nil, fmt.Errorf("decrypted key contains %d bytes instead of 16", len(decrypted))
	}
	return decrypted, nil
}

func decryptKeyringPassword(encoded string, key, iv []byte) (string, error) {
	decrypted, err := decryptKeyringValue(encoded, key, iv)
	if err != nil {
		return "", err
	}
	if len(decrypted) <= 8 {
		return "", errors.New("decrypted password record is too short")
	}
	padding := int(decrypted[len(decrypted)-1])
	if padding < 1 || padding > aes.BlockSize || padding > len(decrypted)-8 {
		return "", errors.New("decrypted password has invalid padding")
	}
	for _, value := range decrypted[len(decrypted)-padding:] {
		if int(value) != padding {
			return "", errors.New("decrypted password has invalid padding")
		}
	}
	payload := decrypted[8 : len(decrypted)-padding]
	if index := bytes.IndexByte(payload, 0); index >= 0 {
		payload = payload[:index]
	}
	if len(payload) == 0 || !utf8.Valid(payload) {
		return "", errors.New("decrypted password is empty or invalid UTF-8")
	}
	password := string(payload)
	for _, value := range password {
		if unicode.IsControl(value) {
			return "", errors.New("decrypted password contains control characters")
		}
	}
	return password, nil
}

func decryptKeyringValue(encoded string, key, iv []byte) ([]byte, error) {
	encrypted, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(encrypted) == 0 || len(encrypted)%aes.BlockSize != 0 || len(encrypted) > maxKeyringBytes {
		return nil, errors.New("encrypted keyring value is invalid base64 or block length")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	result := make([]byte, len(encrypted))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(result, encrypted)
	return result, nil
}

func validateIndividualAddress(value string) error {
	parts := strings.Split(value, ".")
	limits := []uint64{15, 15, 255}
	if len(parts) != len(limits) {
		return fmt.Errorf("individual address %q must use area.line.device", value)
	}
	for index, part := range parts {
		parsed, err := strconv.ParseUint(part, 10, 8)
		if err != nil || parsed > limits[index] {
			return fmt.Errorf("individual address %q is out of range", value)
		}
	}
	return nil
}

func canonicalGroupAddress(value string) (string, error) {
	parts := strings.Split(value, "/")
	limits := []uint64{31, 7, 255}
	if len(parts) != len(limits) {
		return "", fmt.Errorf("group address %q must use main/middle/sub", value)
	}
	values := make([]uint64, len(parts))
	for index, part := range parts {
		parsed, err := strconv.ParseUint(part, 10, 8)
		if err != nil || parsed > limits[index] {
			return "", fmt.Errorf("group address %q is out of range", value)
		}
		values[index] = parsed
	}
	return fmt.Sprintf("%d/%d/%d", values[0], values[1], values[2]), nil
}

func parseBoundedUint(value string, max uint64) (uint64, error) {
	if value == "" {
		return 0, nil
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || parsed > max {
		return 0, fmt.Errorf("must be between 0 and %d", max)
	}
	return parsed, nil
}
