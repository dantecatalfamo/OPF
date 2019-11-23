package main

import (
	"strings"
	"strconv"
	"os/exec"
	"fmt"
)

func splitIp(ip string) (string, int, error) {
	if strings.Contains(ip, ".") {
		ipSplit := strings.Split(ip, ":")
		port, err := strconv.Atoi(ipSplit[1])
		if err != nil {
			return "", 0, err
		}
		return ipSplit[0], port, nil
	} else {
		ipSplit := strings.Split(ip, "[")
		portStr := strings.Trim(ipSplit[1], "]")
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return "", 0, err
		}
		return ipSplit[0], port, nil
	}
}

type PfState struct {
	Proto           string `json:"proto"`
	Age             string `json:"age"`
	Id              string `json:"id"`
	Expires         string `json:"expires"`
	State           string `json:"state"`
	Gateway         string `json:"gateway"`
	SourceIP        string `json:"sourceIp"`
	DestinationIP   string `json:"destinationIp"`
	SourcePort      int    `json:"sourcePort"`
	DestinationPort int    `json:"destinationPort"`
	PacketsSent     int    `json:"packetsSent"`
	PacketsReveived int    `json:"packetsReceived"`
	BytesSent       int    `json:"bytesSent"`
	BytesReived     int    `json:"butesReceived"`
	Rule            int    `json:"rule"`
	Direction       string `json:"direction"`
}

func genPfState(lines []string) (*PfState, error) {
	pfState := &PfState{}
	var src string
	var dst string
	var dirArrow string
	var dir string
	var gw string

	summaryLine := strings.Fields(lines[0])
	proto := summaryLine[1]
	state := summaryLine[len(summaryLine)-1]

	if []rune(summaryLine[3])[0] == '(' {
		dirArrow = summaryLine[4]
		gwStr := summaryLine[3]
		gw = gwStr[1 : len(gw)-2]
	} else {
		dirArrow = summaryLine[3]
	}

	if dirArrow == "<-" {
		dir = "in"
		dst = summaryLine[2]
		src = summaryLine[4]
	} else {
		dir = "out"
		src = summaryLine[2]
		if gw == "" {
			dst = summaryLine[4]
		} else {
			dst = summaryLine[5]
		}
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

	bytesRecv, err := strconv.Atoi(bytes[0])
	if err != nil {
		return nil, err
	}

	rule, err := strconv.Atoi(details[10])
	if err != nil {
		return nil, err
	}

	var idLine string

	if proto == "tcp" {
		idLine = lines[3]
	} else {
		idLine = lines[2]
	}

	idFields := strings.Fields(idLine)
	id := idFields[1]

	pfState.Proto = proto
	pfState.Direction = dir
	pfState.Gateway = gw
	pfState.DestinationIP = dstIp
	pfState.DestinationPort = dstPort
	pfState.SourceIP = srcIp
	pfState.SourcePort = srcPort
	pfState.State = state
	pfState.Age = age
	pfState.Expires = expires
	pfState.PacketsSent = pktSent
	pfState.PacketsReveived = pktRecv
	pfState.BytesSent = bytesSent
	pfState.BytesReived = bytesRecv
	pfState.Rule = rule
	pfState.Id = id

	return pfState, nil
}

func groupIndent(lines []string) [][]string {
	var groups [][]string
	var group []string

	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		if []rune(line)[0] != ' ' {
			if len(group) > 0 {
				groups = append(groups, group)
			}
			group = nil
			group = append(group, line)
		} else {
			group = append(group, line)
		}
	}

	groups = append(groups, group)

	return groups
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
