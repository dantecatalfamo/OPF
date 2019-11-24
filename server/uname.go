package main

import (
	"os/exec"
	"strings"
)

type Uname struct {
	Hardware  string `json:"hardware"`
	NodeName  string `json:"nodeName"`
	OSRelease string `json:"osRelease"`
	OSName    string `json:"osName"`
	OSVersion string `json:"osVersion"`
}

func uname() (*Uname, error) {
	outBytes, err := exec.Command("uname", "-a").Output()
	if err != nil {
		return nil, err
	}

	out := string(outBytes)
	fields := strings.Fields(out)
	osName := fields[0]
	nodeName := fields[1]
	osRelese := fields[2]
	osVersion := fields[3]
	hardware := fields[4]

	un := &Uname{}

	un.Hardware = hardware
	un.NodeName = nodeName
	un.OSRelease = osRelese
	un.OSName = osName
	un.OSVersion = osVersion

	return un, nil
}
