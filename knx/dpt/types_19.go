// Copyright 2026 Hongjie Li.
// Licensed under the MIT license which can be found in the LICENSE file.

package dpt

import (
	"fmt"
	"time"
)

// DPT_19001 represents DPT 19.001 / DateTime.
// Years are represented as an offset from 1900 and therefore range from 1900
// through 2155. Special24 represents the time-only value 24:00:00.
type DPT_19001 struct {
	Date          time.Time
	Special24     bool
	Fault         bool
	WorkingDay    bool
	NoWorkingDay  bool
	NoYear        bool
	NoDate        bool
	NoDayOfWeek   bool
	NoTime        bool
	SummerTime    bool
	ClockQuality  bool
	ExternalClock bool
}

func (d DPT_19001) Pack() []byte {
	buffer := make([]byte, 9)
	if !d.IsValid() {
		return buffer
	}
	workingDay := d.WorkingDay
	if d.Special24 {
		buffer[4] = 24
	} else {
		buffer[1] = uint8(d.Date.Year() - 1900)
		buffer[2] = uint8(d.Date.Month())
		buffer[3] = uint8(d.Date.Day())
		weekday := uint8(d.Date.Weekday())
		if weekday == 0 {
			weekday = 7
		}
		workingDay = weekday <= 5
		buffer[4] = weekday<<5 | uint8(d.Date.Hour())
		buffer[5] = uint8(d.Date.Minute())
		buffer[6] = uint8(d.Date.Second())
		d.SummerTime = d.Date.IsDST()
	}
	setDPT19Flag(&buffer[7], 0x80, d.Fault)
	setDPT19Flag(&buffer[7], 0x40, workingDay)
	setDPT19Flag(&buffer[7], 0x20, d.NoWorkingDay)
	setDPT19Flag(&buffer[7], 0x10, d.NoYear)
	setDPT19Flag(&buffer[7], 0x08, d.NoDate)
	setDPT19Flag(&buffer[7], 0x04, d.NoDayOfWeek)
	setDPT19Flag(&buffer[7], 0x02, d.NoTime)
	setDPT19Flag(&buffer[7], 0x01, d.SummerTime)
	setDPT19Flag(&buffer[8], 0x80, d.ClockQuality)
	setDPT19Flag(&buffer[8], 0x40, d.ExternalClock)
	return buffer
}

func setDPT19Flag(target *byte, mask byte, enabled bool) {
	if enabled {
		*target |= mask
	}
}

func (d *DPT_19001) Unpack(data []byte) error {
	if len(data) != 9 {
		return ErrInvalidLength
	}
	if data[8]&0x3f != 0 {
		return fmt.Errorf("payload contains reserved flag bits")
	}
	year, month, day := int(data[1])+1900, time.Month(data[2]&0x0f), int(data[3]&0x1f)
	weekday, hour := uint8(data[4]>>5), int(data[4]&0x1f)
	minute, second := int(data[5]&0x3f), int(data[6]&0x3f)
	if hour == 24 {
		if minute != 0 || second != 0 {
			return fmt.Errorf("payload is out of range")
		}
		d.Special24 = true
		d.Date = time.Time{}
	} else {
		if weekday > 7 || hour > 23 || minute > 59 || second > 59 {
			return fmt.Errorf("payload is out of range")
		}
		d.Special24 = false
		d.Date = time.Date(year, month, day, hour, minute, second, 0, time.UTC)
		if d.Date.Year() != year || d.Date.Month() != month || d.Date.Day() != day {
			return fmt.Errorf("payload is out of range")
		}
	}
	d.Fault = data[7]&0x80 != 0
	d.WorkingDay = data[7]&0x40 != 0
	d.NoWorkingDay = data[7]&0x20 != 0
	d.NoYear = data[7]&0x10 != 0
	d.NoDate = data[7]&0x08 != 0
	d.NoDayOfWeek = data[7]&0x04 != 0
	d.NoTime = data[7]&0x02 != 0
	d.SummerTime = data[7]&0x01 != 0
	d.ClockQuality = data[8]&0x80 != 0
	d.ExternalClock = data[8]&0x40 != 0
	if !d.IsValid() {
		return fmt.Errorf("payload is out of range")
	}
	return nil
}

func (d DPT_19001) IsValid() bool {
	if d.Special24 {
		return !d.NoTime
	}
	if d.Date.IsZero() || d.Date.Year() < 1900 || d.Date.Year() > 2155 {
		return false
	}
	return true
}

func (d DPT_19001) Unit() string { return "" }

func (d DPT_19001) String() string {
	if d.Special24 {
		return "24:00:00"
	}
	if d.NoTime {
		return d.Date.Format("2006-01-02")
	}
	if d.NoYear && d.NoDate && d.NoDayOfWeek {
		return d.Date.Format("15:04:05")
	}
	return d.Date.Format("2006-01-02 15:04:05")
}
