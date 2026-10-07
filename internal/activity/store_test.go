package activity

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
)

// A name seen more than 1/Cap of the time is kept, with a count no less
// than the true one, however many others come and go.
func TestTopKKeepsFrequentNames(t *testing.T) {
	k := newTopK(10)
	for i := 0; i < 10000; i++ {
		if i%5 == 0 {
			k.Add("often.example", int64(i), "", "")
		} else {
			k.Add(fmt.Sprintf("random-%d.example", i), int64(i), "", "")
		}
	}
	if len(k.Items) != 10 {
		t.Fatalf("%d items, cap 10", len(k.Items))
	}
	top := Top([]*TopK{&k}, 1)
	if top[0].Name != "often.example" || top[0].Count < 2000 || top[0].Count-top[0].Err > 2000 {
		t.Errorf("top = %+v", top[0])
	}
}

func TestTopMergesDays(t *testing.T) {
	a, b := newTopK(5), newTopK(5)
	a.Add("x", 1, "ads", "*.x")
	a.Add("y", 1, "", "")
	b.Add("x", 2, "trackers", "x")
	b.Add("y", 1, "", "")
	b.Add("y", 1, "", "")
	top := Top([]*TopK{&a, &b}, 5)
	if len(top) != 2 || top[0].Name != "y" || top[0].Count != 3 || top[1].Count != 2 || top[1].List != "trackers" || top[1].Entry != "x" {
		t.Errorf("%+v", top)
	}
}

var day0 = time.Date(2026, 10, 7, 9, 30, 0, 0, time.Local)

func TestStoreCounts(t *testing.T) {
	s := &Store{}
	s.AddAnswer(Answer{Time: day0, Device: "aa", Address: "192.168.1.5", Name: "example.com", Rcode: "NOERROR"}, false)
	s.AddAnswer(Answer{Time: day0, Device: "aa", Address: "192.168.1.5", Name: "example.com", Rcode: "NOERROR", Cached: true}, false)
	s.AddAnswer(Answer{Time: day0.Add(time.Hour), Device: "bb", Address: "192.168.1.6", Name: "nope.example", Rcode: "NXDOMAIN"}, false)
	s.AddBlock(Block{Time: day0.Add(time.Hour), Device: "bb", Address: "192.168.1.6", Name: "ads.example", List: "ads", Entry: "*.ads.example"})
	// The block's own answer: a query, not a name looked up or an
	// NXDOMAIN.
	s.AddAnswer(Answer{Time: day0.Add(time.Hour), Device: "bb", Address: "192.168.1.6", Name: "ads.example", Rcode: "NXDOMAIN"}, true)
	s.AddBlock(Block{Time: day0.Add(time.Hour), Device: "bb", Name: "fine.example", Pass: true})

	sum := s.Summary(day0.Add(2*time.Hour), 1, 10)
	want := Counts{Queries: 4, Blocked: 1, Allowed: 1, NXDomain: 1, Cached: 1}
	if sum.Total != want {
		t.Errorf("total %+v, want %+v", sum.Total, want)
	}
	if len(sum.Hours) != 2 || sum.ByList["ads"] != 1 {
		t.Errorf("hours %+v byList %+v", sum.Hours, sum.ByList)
	}
	if len(sum.Names) != 1 || sum.Names[0].Name != "example.com" || sum.Names[0].Count != 2 {
		t.Errorf("names %+v", sum.Names)
	}
	if len(sum.Blocked) != 1 || sum.Blocked[0].List != "ads" {
		t.Errorf("blocked %+v", sum.Blocked)
	}
	// Most queries first, then by key; the allowed name came with no
	// address, which doesn't blank the one it had.
	if len(sum.Devices) != 2 || sum.Devices[1].Key != "bb" || sum.Devices[1].Queries != 2 || sum.Devices[1].Blocked != 1 || sum.Devices[1].Address != "192.168.1.6" {
		t.Errorf("devices %+v", sum.Devices)
	}
	// The name that didn't exist; the block's NXDOMAIN isn't one.
	if len(sum.Missing) != 1 || sum.Missing[0].Name != "nope.example" {
		t.Errorf("missing %+v", sum.Missing)
	}
	d, ok := s.Device("bb", day0.Add(2*time.Hour), 1, 10)
	if !ok || d.Total.Blocked != 1 || d.Total.NXDomain != 1 || len(d.Blocked) != 1 || len(d.Names) != 0 || len(d.Missing) != 1 {
		t.Errorf("device %+v %v", d, ok)
	}
	if _, ok := s.Device("cc", day0, 1, 10); ok {
		t.Error("a device never seen")
	}
}

// Past MaxDevices in a day, the rest count as one.
func TestStoreCapsDevices(t *testing.T) {
	s := &Store{}
	for i := 0; i < MaxDevices+20; i++ {
		s.AddAnswer(Answer{Time: day0, Device: fmt.Sprint("dev", i), Name: "a.example", Rcode: "NOERROR"}, false)
	}
	sum := s.Summary(day0, 1, 10)
	if len(sum.Devices) != MaxDevices+1 {
		t.Fatalf("%d devices", len(sum.Devices))
	}
	for _, d := range sum.Devices {
		if d.Key == Other && d.Queries != 20 {
			t.Errorf("other: %+v", d)
		}
	}
}

func TestStorePruneAndForget(t *testing.T) {
	s := &Store{}
	for i := 0; i < 5; i++ {
		at := day0.AddDate(0, 0, i)
		s.AddAnswer(Answer{Time: at, Device: "aa", Name: "a.example", Rcode: "NOERROR"}, false)
		s.AddAnswer(Answer{Time: at, Device: "bb", Name: "b.example", Rcode: "NOERROR"}, false)
	}
	now := day0.AddDate(0, 0, 4)
	s.Prune(now, 2, true)
	if len(s.Days) != 2 || len(s.Hours) != 2 {
		t.Fatalf("%d days, %d hours after pruning to 2", len(s.Days), len(s.Hours))
	}
	s.ForgetDevice("aa")
	if _, ok := s.Device("aa", now, 2, 10); ok {
		t.Error("forgotten device still there")
	}
	if _, ok := s.Device("bb", now, 2, 10); !ok {
		t.Error("forgot the other device too")
	}
	s.Prune(now, 2, false)
	if sum := s.Summary(now, 2, 10); len(sum.Devices) != 0 || sum.Total.Queries != 4 {
		t.Errorf("devices off: %+v", sum)
	}
}

func TestStoreSaveLoad(t *testing.T) {
	s := &Store{Log: LogPosition{Inode: 7, Offset: 123}}
	s.AddAnswer(Answer{Time: day0, Device: "aa", Name: "a.example", Rcode: "NOERROR"}, false)
	s.AddBlock(Block{Time: day0, Device: "aa", Name: "ads.example", List: "ads"})
	var buf bytes.Buffer
	if err := s.Save(&buf); err != nil {
		t.Fatal(err)
	}
	saved := buf.String()
	l, err := Load(strings.NewReader(saved))
	if err != nil {
		t.Fatal(err)
	}
	if l.Log != s.Log || l.Summary(day0, 1, 5).Total != s.Summary(day0, 1, 5).Total {
		t.Errorf("loaded %+v", l)
	}
	// Adding after loading finds what's there.
	l.AddAnswer(Answer{Time: day0, Device: "aa", Name: "a.example", Rcode: "NOERROR"}, false)
	if d, _ := l.Device("aa", day0, 1, 5); len(d.Names) != 1 || d.Names[0].Count != 2 {
		t.Errorf("after loading: %+v", d.Names)
	}
	// A damaged file: the caps come from the code, out-of-order and
	// empty entries are refused.
	big := strings.Replace(saved, `"cap":25`, `"cap":1000000`, 1)
	if l, err := Load(strings.NewReader(big)); err != nil || l.Days[0].Devices["aa"].Names.Cap != DeviceTop {
		t.Errorf("cap from the file: %v", err)
	}
	for _, bad := range []string{
		`{"hours":[{"start":10},{"start":5}]}`,
		`{"days":[null]}`,
		`{"hours":[null]}`,
		`not json`,
	} {
		if _, err := Load(strings.NewReader(bad)); err == nil {
			t.Errorf("loaded %s", bad)
		}
	}
}

// One of the network's names: in which hours, and by which devices.
func TestStoreName(t *testing.T) {
	s := &Store{}
	at := time.Date(2026, 10, 7, 9, 10, 0, 0, time.Local)
	for i := 0; i < 3; i++ {
		s.AddAnswer(Answer{Time: at, Device: "aa", Name: "a.example", Rcode: "NOERROR"}, false)
	}
	s.AddAnswer(Answer{Time: at.Add(2 * time.Hour), Device: "bb", Name: "a.example", Rcode: "NOERROR"}, false)
	s.AddBlock(Block{Time: at, Device: "bb", Name: "ads.example", List: "ads", Entry: "*.ads.example"})
	s.AddAnswer(Answer{Time: at, Name: "a.example", Rcode: "NOERROR"}, false) // devices not kept for this one

	n, ok := s.Name(ListNames, "a.example", at.Add(3*time.Hour), 1)
	if !ok || n.Count != 5 || len(n.Hours) != 2 || n.Hours[0].Count != 4 || n.Hours[0].Start.Hour() != 9 || n.Hours[1].Start.Hour() != 11 {
		t.Fatalf("%+v %v", n, ok)
	}
	if len(n.Devices) != 2 || n.Devices[0] != (DeviceCount{Key: "aa", Count: 3}) || n.Devices[1].Key != "bb" {
		t.Errorf("devices %+v", n.Devices)
	}
	b, ok := s.Name(ListBlocked, "ads.example", at, 1)
	if !ok || b.BlockList != "ads" || b.Entry != "*.ads.example" || len(b.Devices) != 1 {
		t.Errorf("blocked %+v", b)
	}
	if _, ok := s.Name(ListNames, "ads.example", at, 1); ok {
		t.Error("a blocked name among those looked up")
	}
	if _, ok := s.Name("bogus", "a.example", at, 1); ok {
		t.Error("a list that isn't one")
	}
	// The summary's lists don't carry every name's when and who.
	if sum := s.Summary(at, 1, 10); sum.Names[0].Hours != nil || sum.Names[0].Devices != nil {
		t.Errorf("summary carries detail: %+v", sum.Names[0])
	}
}

// A name's devices are bounded too: past ItemDevices, Space-Saving.
func TestStoreNameDevicesBounded(t *testing.T) {
	s := &Store{}
	for i := 0; i < 50; i++ {
		s.AddAnswer(Answer{Time: day0, Device: fmt.Sprint("dev", i), Name: "a.example", Rcode: "NOERROR"}, false)
	}
	for i := 0; i < 20; i++ {
		s.AddAnswer(Answer{Time: day0, Device: "busy", Name: "a.example", Rcode: "NOERROR"}, false)
	}
	n, _ := s.Name(ListNames, "a.example", day0, 1)
	if len(n.Devices) != ItemDevices || n.Devices[0].Key != "busy" {
		t.Errorf("%+v", n.Devices)
	}
}

// The worst a day can be with when and who: every list full, each name
// asked for in every hour by a full list of devices.
func TestStoreWorstDaySize(t *testing.T) {
	s := &Store{}
	at := midnight(day0)
	for n := 0; n < NetworkTop; n++ {
		for h := 0; h < 24; h++ {
			for d := 0; d < ItemDevices; d++ {
				tm := at.Add(time.Duration(h) * time.Hour)
				dev := fmt.Sprintf("mac:02:00:00:00:%02x:%02x", d, n%12) // 120 devices, under MaxDevices
				name := fmt.Sprintf("name-%03d.some-longish-domain.example.com", n)
				s.AddAnswer(Answer{Time: tm, Device: dev, Address: "192.168.100.200", Name: name, Rcode: "NOERROR"}, false)
				s.AddAnswer(Answer{Time: tm, Device: dev, Address: "192.168.100.200", Name: "x" + name, Rcode: "NXDOMAIN"}, false)
				s.AddBlock(Block{Time: tm, Device: dev, Address: "192.168.100.200", Name: "ads." + name, List: "hagezi-pro", Entry: "*." + name})
			}
		}
	}
	var buf bytes.Buffer
	s.Save(&buf)
	with := buf.Len()
	for _, d := range s.Days {
		for _, l := range []*TopK{&d.Names, &d.Blocked, &d.Missing} {
			for i := range l.Items {
				l.Items[i].Hours, l.Items[i].Devices = nil, nil
			}
		}
	}
	buf.Reset()
	s.Save(&buf)
	t.Logf("a worst-case day: %d KB saved, %d KB of it when and who", with/1024, (with-buf.Len())/1024)
	// A month of such days (about 32 MB) is still read back.
	if 31*with > maxFileSize {
		t.Errorf("a month of worst days is %d MB", 31*with>>20)
	}
}
