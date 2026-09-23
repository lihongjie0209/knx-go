package knxsecure

import (
	"archive/zip"
	"bytes"
	"testing"
)

const testKeyringXML = `<?xml version="1.0" encoding="utf-8"?>
<Keyring CreatedBy="UnitTest" Created="2024-10-03T12:34:56Z">
  <Interface Type="Tunnelling" IndividualAddress="1.1.1" UserID="5" Password="9b1seR1kYPayZxTITA4mq3oRNSdkelNCOnHA0jtZK6g=" Authentication="6/b5wvUrvyg4J+JH+J3EPvaGbIug0amjx5PMHkztZUQ=">
    <Group Address="1/2/3" Senders="1.1.1 1.1.10" />
  </Interface>
  <Backbone Key="XvI24ir4JEE0cxRMsMKtbw==" Latency="20" MulticastAddress="224.0.23.12" />
  <GroupAddresses><Group Address="1/2/3" Key="DFZA8HL9wnFWS3LGw40k/w==" /></GroupAddresses>
  <Devices><Device IndividualAddress="1.1.10" ToolKey="dxJwaArmxpY3eftE9Qzj3Q==" ManagementPassword="pijNuGYx6LA+7ZJ4vyWtUMTfuPFXEIEL5A8lmHadX6A=" Authentication="dMWy3GlA8iHV7cflIRyp7S0dBxyEiHFTWIE7qdMh6u4=" SequenceNumber="42" SerialNumber="12345678" /></Devices>
</Keyring>`

func TestLoadKeyringXML(t *testing.T) {
	keyring, err := LoadKeyring([]byte(testKeyringXML), "knxPassword")
	if err != nil {
		t.Fatal(err)
	}
	if keyring.CreatedBy != "UnitTest" || keyring.Created != "2024-10-03T12:34:56Z" {
		t.Fatalf("metadata=%#v", keyring)
	}
	iface := keyring.Interfaces["1.1.1"]
	if iface.UserID != 5 || iface.Password != "ifPass123" || iface.Authentication != "ifAuth456" || len(iface.Groups["1/2/3"]) != 2 {
		t.Fatalf("interface=%#v", iface)
	}
	if !bytes.Equal(keyring.GroupKeys["1/2/3"], mustHex(t, "00112233445566778899aabbccddeeff")) {
		t.Fatalf("group key=%x", keyring.GroupKeys["1/2/3"])
	}
	if len(keyring.Backbones) != 1 || !bytes.Equal(keyring.Backbones[0].Key, mustHex(t, "8899aabbccddeeff0011223344556677")) {
		t.Fatalf("backbones=%#v", keyring.Backbones)
	}
	device := keyring.Devices["1.1.10"]
	if !bytes.Equal(device.ToolKey, mustHex(t, "aabbccddeeff00112233445566778899")) || device.ManagementPassword != "devMgmt789" || device.Authentication != "devAuth987" || device.SequenceNumber != 42 {
		t.Fatalf("device=%#v", device)
	}
}

func TestLoadKeyringZIP(t *testing.T) {
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	entry, err := writer.Create("project.xml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte(testKeyringXML)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	keyring, err := LoadKeyring(archive.Bytes(), "knxPassword")
	if err != nil || keyring.Interfaces["1.1.1"].Password != "ifPass123" {
		t.Fatalf("keyring=%#v err=%v", keyring, err)
	}
}

func TestLoadKeyringRejectsMalformedAndWrongPassword(t *testing.T) {
	for _, test := range []struct {
		name, xml, password string
	}{
		{name: "wrong root", xml: `<Other/>`, password: "x"},
		{name: "duplicate group", xml: `<Keyring Created="x"><GroupAddresses><Group Address="1/2/3" Key="AAAAAAAAAAAAAAAAAAAAAA=="/><Group Address="1/2/3" Key="AAAAAAAAAAAAAAAAAAAAAA=="/></GroupAddresses></Keyring>`, password: "x"},
		{name: "bad address", xml: `<Keyring Created="x"><Interface IndividualAddress="20.1.1"/></Keyring>`, password: "x"},
		{name: "wrong password", xml: testKeyringXML, password: "wrong"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := LoadKeyring([]byte(test.xml), test.password); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	if _, err := LoadKeyring(make([]byte, maxKeyringBytes+1), "x"); err == nil {
		t.Fatal("expected size error")
	}
}
