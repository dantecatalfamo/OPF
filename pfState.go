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

func stringsToState(pfStrings []string) (*PfState, error) {
	pfState := &PfState{}
	var src string
	var dst string
	var dir string
	var gw string

	summary := strings.Fields(pfStrings[0])
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

	dstIp, dstPort, err := splitIp(dst)
	if err != nil {
		return nil, err
	}

	srcIp, srcPort, err := splitIp(src)
	if err != nil {
		return nil, err
	}

	pfState.DestinationIP = dstIp
	pfState.DestinationPort = dstPort
	pfState.SourceIP = srcIp
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
		state, err := stringsToState(group)
		if err != nil {
			fmt.Println(err)
			continue
		}
		states = append(states, state)
	}

	return states, nil
}
