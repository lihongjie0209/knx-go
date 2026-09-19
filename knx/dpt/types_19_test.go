package dpt

import (
	"testing"
	"time"
)

func TestDPT19001RoundTrip(t *testing.T) {
	source := DPT_19001{Date: time.Date(2026, time.September, 20, 14, 35, 42, 0, time.FixedZone("CEST", 2*60*60)), ClockQuality: true, ExternalClock: true}
	packed := source.Pack()
	if len(packed) != 9 {
		t.Fatalf("length=%d", len(packed))
	}
	var decoded DPT_19001
	if err := decoded.Unpack(packed); err != nil {
		t.Fatal(err)
	}
	if !decoded.IsValid() || decoded.Date.Year() != 2026 || decoded.Date.Month() != time.September || decoded.Date.Day() != 20 || decoded.Date.Hour() != 14 || decoded.Date.Minute() != 35 || decoded.Date.Second() != 42 || !decoded.ClockQuality || !decoded.ExternalClock {
		t.Fatalf("decoded=%#v", decoded)
	}
}

func TestDPT19001RejectsInvalidValues(t *testing.T) {
	for _, value := range []DPT_19001{
		{Date: time.Date(1899, 1, 1, 0, 0, 0, 0, time.UTC)},
		{Date: time.Date(2156, 1, 1, 0, 0, 0, 0, time.UTC)},
		{Special24: true, NoTime: true},
	} {
		if value.IsValid() {
			t.Fatalf("expected invalid value %#v", value)
		}
	}
	var decoded DPT_19001
	if err := decoded.Unpack([]byte{0, 126, 9, 20, 24, 1, 0, 0, 0}); err == nil {
		t.Fatal("expected invalid 24:01:00")
	}
}
