package pf

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

// The UI's sample model (ui/src/model/sample-model.json) is also what
// the mock server starts from. Decoding it strictly catches fields the
// TypeScript model has and the Go model doesn't; re-encoding and
// comparing catches fields Go reads but would drop or change on save.
const sampleModelPath = "../../ui/src/model/sample-model.json"

func loadSampleModel(t *testing.T) (*Model, []byte) {
	t.Helper()
	data, err := os.ReadFile(sampleModelPath)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var m Model
	if err := dec.Decode(&m); err != nil {
		t.Fatalf("sample model doesn't match the Go model: %v", err)
	}
	return &m, data
}

func TestSampleModelMatchesGoModel(t *testing.T) {
	m, data := loadSampleModel(t)
	again, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var want, got any
	if err := json.Unmarshal(data, &want); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(again, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(want, got) {
		t.Errorf("sample model changes when saved by Go:\n%s", jsonDiff(want, got, ""))
	}
}

func TestSampleModelGenerates(t *testing.T) {
	m, _ := loadSampleModel(t)
	conf := GeneratePfConf(m)
	for _, want := range []string{"$lan:network", "($wan)", "<bruteforce>", "rdr-to 192.168.1.20"} {
		if !strings.Contains(conf, want) {
			t.Errorf("pf.conf from the sample model is missing %q", want)
		}
	}
}

// jsonDiff lists the paths where two decoded JSON values differ.
func jsonDiff(a, b any, path string) string {
	switch av := a.(type) {
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok {
			return path + ": object vs " + describe(b) + "\n"
		}
		var out string
		for k := range av {
			out += jsonDiff(av[k], bv[k], path+"."+k)
		}
		for k := range bv {
			if _, ok := av[k]; !ok {
				out += path + "." + k + ": added\n"
			}
		}
		return out
	case []any:
		bv, ok := b.([]any)
		if !ok || len(av) != len(bv) {
			return path + ": array differs\n"
		}
		var out string
		for i := range av {
			out += jsonDiff(av[i], bv[i], path+"["+string(rune('0'+i%10))+"]")
		}
		return out
	}
	if !reflect.DeepEqual(a, b) {
		return path + ": " + describe(a) + " vs " + describe(b) + "\n"
	}
	return ""
}

func describe(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
