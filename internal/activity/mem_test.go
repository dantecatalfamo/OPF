package activity

import (
	"bytes"
	"fmt"
	"runtime"
	"testing"
	"time"
)

// What a worst-case day takes in memory, against what it takes saved.
func TestStoreWorstDayMemory(t *testing.T) {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	s := &Store{}
	at := midnight(day0)
	for n := 0; n < NetworkTop; n++ {
		for h := 0; h < 24; h++ {
			for d := 0; d < ItemDevices; d++ {
				tm := at.Add(time.Duration(h) * time.Hour)
				dev := fmt.Sprintf("mac:02:00:00:00:%02x:%02x", d, n%12)
				name := fmt.Sprintf("name-%03d.some-longish-domain.example.com", n)
				s.AddAnswer(Answer{Time: tm, Device: dev, Address: "192.168.100.200", Name: name, Rcode: "NOERROR"}, false)
				s.AddAnswer(Answer{Time: tm, Device: dev, Address: "192.168.100.200", Name: "x" + name, Rcode: "NXDOMAIN"}, false)
				s.AddBlock(Block{Time: tm, Device: dev, Address: "192.168.100.200", Name: "ads." + name, List: "hagezi-pro", Entry: "*." + name})
			}
		}
	}
	// Loaded from a file, as after a restart: no strings shared with the
	// test's.
	var buf bytes.Buffer
	s.Save(&buf)
	data := buf.Bytes()
	s = nil
	runtime.GC()
	runtime.ReadMemStats(&before)
	l, err := Load(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	t.Logf("a worst-case day: %d KB in memory, %d KB saved", (int64(after.HeapAlloc)-int64(before.HeapAlloc))/1024, len(data)/1024)
	runtime.KeepAlive(l)
	runtime.KeepAlive(data)
}
