package main

import (
	"fmt"
	"math"
	"os"
	"strings"
	"time"

	"github.com/dantecatalfamo/OPF/internal/activity"
)

// The mock's traffic per device: pf's table of counters, growing with
// time for the devices its ARP table has, and a few days already kept,
// so the pages have history to show.

// mockTalkers are the devices, each with how much it moves on average,
// bytes a second, received (downloads) and sent.
var mockTalkers = []struct {
	addr, mac      string
	received, sent float64
}{
	{"192.168.1.112", "3c:22:fb:91:04:7d", 420_000, 38_000}, // a laptop streaming
	{"192.168.1.118", "f0:18:98:2e:aa:13", 180_000, 22_000},
	{"192.168.1.20", "00:1b:21:3a:4f:10", 40_000, 260_000}, // the file server, backing up
	{"192.168.1.25", "00:1b:21:3a:4f:22", 25_000, 9_000},
	{"192.168.1.40", "a4:5d:36:0c:81:9e", 1_200, 600}, // the printer
	{"192.168.20.101", "68:57:2d:10:e3:41", 900, 2_400},
	{"192.168.20.102", "50:02:91:7c:3a:0f", 3_000, 95_000}, // a camera uploading
	{"10.8.0.2", "", 60_000, 8_000},
}

// mockRate is a rate over the day: busier by day than by night.
func mockRate(avg float64, t time.Time) float64 {
	h := float64(t.Hour()) + float64(t.Minute())/60
	return avg * (1 + 0.8*math.Sin((h-9)/24*2*math.Pi))
}

// mockTrafficTable is pfctl -t opf_hosts -T show -v: each device's
// counters since the mock started.
func mockTrafficTable(start, now time.Time) string {
	var b strings.Builder
	secs := now.Sub(start).Seconds()
	for _, d := range mockTalkers {
		recv := uint64(mockRate(d.received, now) * secs)
		sent := uint64(mockRate(d.sent, now) * secs)
		fmt.Fprintf(&b, "   %s\n\tCleared:     %s\n\tIn/Block:    [ Packets: 0                  Bytes: 0                  ]\n\tIn/Match:    [ Packets: %-18d Bytes: %-18d ]\n\tIn/Pass:     [ Packets: 0                  Bytes: 0                  ]\n\tOut/Block:   [ Packets: 0                  Bytes: 0                  ]\n\tOut/Match:   [ Packets: %-18d Bytes: %-18d ]\n\tOut/Pass:    [ Packets: 0                  Bytes: 0                  ]\n",
			d.addr, start.Format(time.ANSIC), sent/900, sent, recv/1200, recv)
	}
	return b.String()
}

// mockTrafficLabels is pfctl -s labels' unknown traffic: a little, from
// a device that hasn't been seen yet.
func mockTrafficLabels(start, now time.Time) string {
	secs := now.Sub(start).Seconds()
	n := uint64(secs * 2_000)
	// The firewall's own: lookups and downloads, mostly replies.
	sent, recv := uint64(secs*3_500), uint64(secs*21_000)
	return fmt.Sprintf("opf:traffic-unknown:lan 120 %d %d %d %d 0 0 1\nopf:traffic-self:firewall 900 %d %d %d %d %d %d 40\n",
		n/600, n, n/600, n, (sent+recv)/800, sent+recv, sent/200, sent, recv/1200, recv)
}

// seedTraffic writes three days of traffic to the state directory, as
// if it had been kept that long, unless some is there already.
func seedTraffic(path string, now time.Time) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	s := &activity.TrafficStore{}
	for t := now.Add(-72 * time.Hour).Truncate(time.Hour); t.Before(now.Truncate(time.Hour)); t = t.Add(time.Hour) {
		h := &activity.TrafficHour{Start: t.Unix(), Devices: map[string]activity.Bytes{}}
		for _, d := range mockTalkers {
			key := "mac:" + d.mac
			if d.mac == "" {
				key = "vpn:p1"
			}
			b := activity.Bytes{Received: int64(mockRate(d.received, t) * 3600), Sent: int64(mockRate(d.sent, t) * 3600)}
			b.ReceivedPackets, b.SentPackets = b.Received/1200, b.Sent/900
			h.Devices[key] = b
			h.Total.Sent += b.Sent
			h.Total.Received += b.Received
			h.Total.SentPackets += b.SentPackets
			h.Total.ReceivedPackets += b.ReceivedPackets
		}
		h.Unknown = 7_200_000
		h.Firewall = activity.Bytes{Sent: int64(mockRate(3_500, t) * 3600), Received: int64(mockRate(21_000, t) * 3600)}
		s.Hours = append(s.Hours, h)
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return s.Save(f)
}
