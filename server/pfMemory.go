package main

import (
	"os/exec"
	"strconv"
	"strings"
)

type PfMemory struct {
	States       int `json:"states"`
	SrcNodes     int `json:"srcNodes"`
	Frags        int `json:"frags"`
	Tables       int `json:"tables"`
	TableEntries int `json:"tableEntries"`
	PktDelayPkts int `json:"pktDelayPkts"`
}

func genPfMemoryLine(line string) (int, error) {
	fields := strings.Fields(line)
	num := fields[3]
	return strconv.Atoi(num)
}

func GetPfMemory() (*PfMemory, error) {
	outBytes, err := exec.Command("pfctl", "-s", "memory").Output()
	if err != nil {
		return nil, err
	}

	out := string(outBytes)
	lines := strings.Split(out, "\n")

	states, err := genPfMemoryLine(lines[0])
	if err != nil {
		return nil, err
	}

	srcNodes, err := genPfMemoryLine(lines[1])
	if err != nil {
		return nil, err
	}

	frags, err := genPfMemoryLine(lines[2])
	if err != nil {
		return nil, err
	}

	tables, err := genPfMemoryLine(lines[3])
	if err != nil {
		return nil, err
	}

	tableEntries, err := genPfMemoryLine(lines[4])
	if err != nil {
		return nil, err
	}

	pktDelayPkts, err := genPfMemoryLine(lines[5])
	if err != nil {
		return nil, err
	}

	pfm := &PfMemory{}
	pfm.States = states
	pfm.SrcNodes = srcNodes
	pfm.Frags = frags
	pfm.Tables = tables
	pfm.TableEntries = tableEntries
	pfm.PktDelayPkts = pktDelayPkts

	return pfm, nil
}
