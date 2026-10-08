package activity

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestTrafficReadsDeltas(t *testing.T) {
	s := &TrafficStore{}
	who := func(addr string) string {
		if addr == "192.168.1.5" {
			return "mac:aa"
		}
		return ""
	}
	s.Read(day0, map[string]Counter{"192.168.1.5": {Sent: 1000, Received: 5000}, "192.168.1.9": {Sent: 10}}, who)
	s.Read(day0.Add(10*time.Second), map[string]Counter{"192.168.1.5": {Sent: 1500, Received: 9000}, "192.168.1.9": {Sent: 10}}, who)
	// Taken out of the table and put back: it started again.
	s.Read(day0.Add(20*time.Second), map[string]Counter{"192.168.1.5": {Sent: 200, Received: 100}}, who)
	s.ReadUnknown(day0, map[string]uint64{"opf:traffic-unknown:lan": 300})
	s.ReadUnknown(day0.Add(10*time.Second), map[string]uint64{"opf:traffic-unknown:lan": 700})

	sum := s.Summary(day0, 1)
	if sum.Total.Sent != 1700+10 || sum.Total.Received != 9100 || sum.Unknown != 700 {
		t.Errorf("total %+v, unknown %d", sum.Total, sum.Unknown)
	}
	if len(sum.Devices) != 2 || sum.Devices[0].Key != "mac:aa" || sum.Devices[0].Sent != 1700 || sum.Devices[1].Key != "ip:192.168.1.9" {
		t.Errorf("devices %+v", sum.Devices)
	}
	if _, ok := s.Last["192.168.1.9"]; ok {
		t.Error("an address no longer in the table is still followed")
	}
	d, ok := s.Device("mac:aa", day0, 1)
	if !ok || d.Total.Received != 9100 || len(d.Hours) != 1 {
		t.Errorf("device %+v %v", d, ok)
	}
	s.ForgetDevice("mac:aa")
	if sum := s.Summary(day0, 1); len(sum.Devices) != 1 || sum.Total.Sent != 10 {
		t.Errorf("after forgetting: %+v", sum)
	}
}

func TestTrafficCapsAndPrunes(t *testing.T) {
	s := &TrafficStore{}
	c := map[string]Counter{}
	for i := 0; i < MaxDevices+5; i++ {
		c[fmt.Sprintf("10.0.%d.%d", i/250, i%250)] = Counter{Sent: 1}
	}
	s.Read(day0, c, func(a string) string { return "" })
	if sum := s.Summary(day0, 1); len(sum.Devices) != MaxDevices+1 || sum.Total.Sent != int64(MaxDevices+5) {
		t.Errorf("%d devices, %d sent", len(sum.Devices), sum.Total.Sent)
	}
	s.Read(day0.AddDate(0, 0, 3), map[string]Counter{}, func(string) string { return "" })
	s.Prune(day0.AddDate(0, 0, 3), 2)
	if len(s.Hours) != 1 {
		t.Errorf("%d hours after pruning", len(s.Hours))
	}
}

func TestTrafficSaveLoad(t *testing.T) {
	s := &TrafficStore{}
	s.Read(day0, map[string]Counter{"192.168.1.5": {Sent: 1000}}, func(string) string { return "mac:aa" })
	var buf bytes.Buffer
	s.Save(&buf)
	l, err := LoadTraffic(strings.NewReader(buf.String()))
	if err != nil || l.Last["192.168.1.5"].Sent != 1000 {
		t.Fatalf("%+v %v", l, err)
	}
	// After a restart the same counters add nothing.
	l.Read(day0, map[string]Counter{"192.168.1.5": {Sent: 1000}}, func(string) string { return "mac:aa" })
	if sum := l.Summary(day0, 1); sum.Total.Sent != 1000 {
		t.Errorf("counted twice: %+v", sum.Total)
	}
	if _, err := LoadTraffic(strings.NewReader(`{"hours":[{"start":10},{"start":5}]}`)); err == nil {
		t.Error("out of order loaded")
	}
}

// What an hour takes at most, saved, against WorstTrafficHour.
func TestTrafficWorstCase(t *testing.T) {
	s := &TrafficStore{}
	c := map[string]Counter{}
	for i := 0; i < MaxDevices; i++ {
		c[fmt.Sprintf("192.168.%d.%d", i/250, i%250)] = Counter{Sent: 1 << 40, Received: 1 << 40, SentPackets: 1 << 30, ReceivedPackets: 1 << 30}
	}
	s.Read(day0, c, func(a string) string { return "mac:02:00:00:00:00:" + a[len(a)-2:] + a })
	s.Last, s.LastUnknown = nil, nil // counted apart: one per address, not per hour
	var buf bytes.Buffer
	s.Save(&buf)
	t.Logf("a worst-case hour: %d bytes", buf.Len())
	if buf.Len() > WorstTrafficHour {
		t.Errorf("%d bytes, over WorstTrafficHour", buf.Len())
	}
}
