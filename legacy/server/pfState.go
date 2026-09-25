package main

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

type PfState struct {
	Proto            string `json:"proto"`
	Age              string `json:"age"`
	Id               string `json:"id"`
	Expires          string `json:"expires"`
	SourceState      string `json:"sourceState"`
	DestinationState string `json:"destinationState"`
	Gateway          string `json:"gateway"`
	SourceIP         string `json:"sourceIP"`
	DestinationIP    string `json:"destinationIP"`
	SourcePort       int    `json:"sourcePort"`
	DestinationPort  int    `json:"destinationPort"`
	PacketsSent      int    `json:"packetsSent"`
	PacketsReceived  int    `json:"packetsReceived"`
	PacketsTotal     int    `json:"packetsTotal"`
	BytesSent        int    `json:"bytesSent"`
	BytesReceived    int    `json:"bytesReceived"`
	BytesTotal       int    `json:"bytesTotal"`
	Rule             int    `json:"rule"`
	Direction        string `json:"direction"`
}

// genPfState generates a PfState struct from a single row outputted
// from the command pfctl -s states -vv
func genPfState(lines []string) (*PfState, error) {
	var src string
	var dst string
	var srcSt string
	var dstSt string
	var dirArrow string
	var dir string
	var gw string

	summaryLine := strings.Fields(lines[0])
	proto := summaryLine[1]
	state := strings.Split(summaryLine[len(summaryLine)-1], ":")

	if []rune(summaryLine[3])[0] == '(' {
		dirArrow = summaryLine[4]
		srcStr := summaryLine[3]
		src = srcStr[1 : len(srcStr)-2]
	} else {
		dirArrow = summaryLine[3]
	}

	if dirArrow == "<-" {
		dir = "in"
		dst = summaryLine[2]
		src = summaryLine[4]
		srcSt = state[1]
		dstSt = state[0]
	} else {
		if src != "" { // We have a gateway
			dir = "nat"
			gw = summaryLine[2]
			dst = summaryLine[5]
		} else {
			dir = "out"
			dst = summaryLine[4]
			src = summaryLine[2]
		}
		srcSt = state[0]
		dstSt = state[1]
	}

	dstIp, dstPort, err := splitIp(dst)
	if err != nil {
		return nil, err
	}

	srcIp, srcPort, err := splitIp(src)
	if err != nil {
		return nil, err
	}

	var detailLine string
	var details []string

	if proto == "tcp" {
		detailLine = lines[2]
	} else {
		detailLine = lines[1]
	}

	for _, field := range strings.Fields(detailLine) {
		details = append(details, strings.Trim(field, " ,"))
	}

	age := details[1]
	expires := details[4]

	packets := strings.Split(details[5], ":")
	var inPkt string
	var outPkt string
	if dir == "out" {
		outPkt = packets[0]
		inPkt = packets[1]
	} else {
		outPkt = packets[1]
		inPkt = packets[0]
	}

	pktSent, err := strconv.Atoi(outPkt)
	if err != nil {
		return nil, err
	}

	pktRecv, err := strconv.Atoi(inPkt)
	if err != nil {
		return nil, err
	}

	bytes := strings.Split(details[7], ":")
	var inBytes string
	var outBytes string
	if dir == "out" {
		outBytes = bytes[0]
		inBytes = bytes[1]
	} else {
		outBytes = bytes[1]
		inBytes = bytes[0]
	}
	bytesSent, err := strconv.Atoi(outBytes)
	if err != nil {
		return nil, err
	}

	bytesRecv, err := strconv.Atoi(inBytes)
	if err != nil {
		return nil, err
	}

	var rule int
	if len(details) == 9 {
		rule = -1
	} else {
		rule, err = strconv.Atoi(details[10])
		if err != nil {
			return nil, err
		}
	}

	var idLine string

	if proto == "tcp" {
		idLine = lines[3]
	} else {
		idLine = lines[2]
	}

	idFields := strings.Fields(idLine)
	id := idFields[1]

	pfState := &PfState{}

	pfState.Proto = proto
	pfState.Direction = dir
	pfState.Gateway = gw
	pfState.DestinationIP = dstIp
	pfState.DestinationPort = dstPort
	pfState.SourceIP = srcIp
	pfState.SourcePort = srcPort
	pfState.DestinationState = dstSt
	pfState.SourceState = srcSt
	pfState.Age = age
	pfState.Expires = expires
	pfState.PacketsSent = pktSent
	pfState.PacketsReceived = pktRecv
	pfState.PacketsTotal = pktSent + pktRecv
	pfState.BytesSent = bytesSent
	pfState.BytesReceived = bytesRecv
	pfState.BytesTotal = bytesSent + bytesRecv
	pfState.Rule = rule
	pfState.Id = id

	return pfState, nil
}

// GetPfStates generates an array of all current pf states
func GetPfStates() ([]*PfState, error) {
	outBytes, err := exec.Command("doas", "pfctl", "-vv", "-s", "states").Output()
	if err != nil {
		return nil, err
	}

	var states []*PfState

	outString := string(outBytes)
	outLines := strings.Split(outString, "\n")

	groups := groupIndent(outLines)

	for _, group := range groups {
		state, err := genPfState(group)
		if err != nil {
			fmt.Println(err)
			continue
		}
		states = append(states, state)
	}

	return states, nil
}
