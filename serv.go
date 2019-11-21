package main

import (
	"os"
	"os/exec"
	// "io/ioutil"
	// "net/http"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

type PfState struct {
	Proto           string `json:"proto"`
	Age             string `json:"age"`
	Id              string `json:"id"`
	Expires         string `json:"expires"`
	State           string `json:"state"`
	Gateway         string `json:"gateway"`
	SourceIP        string `josn:"source_ip"`
	DestinationIP   string `json:"destination_ip"`
	SourcePort      int    `json:"source_port"`
	DestinationPort int    `json:"destination_port"`
	PacketsSent     int    `json:"packets_sent"`
	PacketsReveived int    `json:"packets_received"`
	BytesSent       int    `json:"bytes_sent"`
	BytesReived     int    `json:"butes_received"`
	Rule            int    `json:"rule"`
	Direction       string `json:"direction"`
}

func stringsToState(pfStrings []string) (*PfState, error) {
	pfState := &PfState{}
	var src string
	var dst string
	var dir string
	var gw string

	summary := strings.Fields(pfStrings[0])
	fmt.Println(summary)
	pfState.Proto = summary[1]

	if []rune(summary[3])[0] == '(' {
		dir = summary[4]
		gw = summary[3]
		pfState.Gateway = gw[1 : len(gw)-2]
	} else {
		dir = summary[3]
	}

	if dir == "<-" {
		pfState.Direction = "in"
		dst = summary[2]
		src = summary[4]
	} else {
		pfState.Direction = "out"
		src = summary[2]
		if gw == "" {
			dst = summary[4]
		} else {
			dst = summary[5]
		}
	}

	dstSplit := strings.Split(dst, ":")
	dstPort, err := strconv.Atoi(dstSplit[1])
	if err != nil {
		return nil, err
	}
	pfState.DestinationIP = dstSplit[0]
	pfState.DestinationPort = dstPort

	srcSplit := strings.Split(src, ":")
	srcPort, err := strconv.Atoi(srcSplit[1])
	if err != nil {
		return nil, err
	}
	pfState.SourceIP = srcSplit[0]
	pfState.SourcePort = srcPort

	pfState.State = summary[len(summary)-1]

	var detailString string
	var details []string

	if pfState.Proto == "tcp" {
		detailString = pfStrings[2]
	} else {
		detailString = pfStrings[1]
	}

	for _, field := range strings.Fields(detailString) {
		details = append(details, strings.Trim(field, " ,"))
	}

	pfState.Age = details[1]
	pfState.Expires = details[4]

	packets := strings.Split(details[5], ":")

	pktSent, err := strconv.Atoi(packets[0])
	if err != nil {
		return nil, err
	}
	pfState.PacketsSent = pktSent

	pktRecv, err := strconv.Atoi(packets[1])
	if err != nil {
		return nil, err
	}
	pfState.PacketsReveived = pktRecv

	bytes := strings.Split(details[7], ":")

	bytesSent, err := strconv.Atoi(bytes[0])
	if err != nil {
		return nil, err
	}
	pfState.BytesSent = bytesSent

	bytesRecv, err := strconv.Atoi(bytes[0])
	if err != nil {
		return nil, err
	}
	pfState.BytesReived = bytesRecv

	rule, err := strconv.Atoi(details[10])
	if err != nil {
		return nil, err
	}
	pfState.Rule = rule

	var ids string

	if pfState.Proto == "tcp" {
		ids = pfStrings[3]
	} else {
		ids = pfStrings[2]
	}

	idFields := strings.Fields(ids)

	pfState.Id = idFields[1]

	return pfState, nil
}

func pfStates() ([]*PfState, error) {
	outBytes, err := exec.Command("pfctl", "-vv", "-s", "states").Output()
	if err != nil {
		return nil, err
	}

	var states []*PfState

	outString := string(outBytes)
	outLines := strings.Split(outString, "\n")

	var stateLines []string
	stateStrings := make([][]string, 0, 50)

	for _, line := range outLines {
		if len(line) == 0 {
			continue
		}
		if []rune(line)[0] != ' ' {
			if len(stateLines) > 0 {
				stateStrings = append(stateStrings, stateLines)
			}
			stateLines = nil
			stateLines = append(stateLines, line)
		} else {
			stateLines = append(stateLines, line)
		}
	}

	for _, ss := range stateStrings {
		state, err := stringsToState(ss)
		if err != nil {
			fmt.Println(err)
			continue
		}
		states = append(states, state)
	}

	return states, nil
}

func main() {
	states, err := pfStates()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	for _, s := range states {
		fmt.Printf("%v\n", s)
	}
	j, err := json.Marshal(states)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(j))
}
