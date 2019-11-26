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
	BytesSent        int    `json:"bytesSent"`
	BytesReceived    int    `json:"bytesReceived"`
	Rule             int    `json:"rule"`
	Direction        string `json:"direction"`
}

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
		gwStr := summaryLine[3]
		gw = gwStr[1 : len(gwStr)-2]
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
		dir = "out"
		src = summaryLine[2]
		if gw == "" {
			dst = summaryLine[4]
		} else {
			dst = summaryLine[5]
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
	pktSent, err := strconv.Atoi(packets[0])
	if err != nil {
		return nil, err
	}

	pktRecv, err := strconv.Atoi(packets[1])
	if err != nil {
		return nil, err
	}

	bytes := strings.Split(details[7], ":")
	bytesSent, err := strconv.Atoi(bytes[0])
	if err != nil {
		return nil, err
	}

	bytesRecv, err := strconv.Atoi(bytes[1])
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
	pfState.BytesSent = bytesSent
	pfState.BytesReceived = bytesRecv
	pfState.Rule = rule
	pfState.Id = id

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
