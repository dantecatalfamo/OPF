package main

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

type netstatInterface struct {
	Name       string `json:"name"`
	Mtu        int    `json:"mtu"`
	Network    string `json:"network"`
	Address    string `json:"address"`
	InPackets  int    `json:"inPackets"`
	InFail     int    `json:"inFail"`
	OutPackets int    `json:"outPackets"`
	OutFail    int    `json:"outFail"`
	Colls      int    `json:"colls"`
}

func genNetstatInterface(line string) (*netstatInterface, error) {
	fields := strings.Fields(line)
	name := fields[0]
	mtu, err := strconv.Atoi(fields[1])
	if err != nil {
		return nil, err
	}
	network := fields[2]

	var address string
	var inPacketsStr string
	var inFailStr string
	var outPacketsStr string
	var outFailStr string
	var collsStr string

	if len(fields) == 8 {
		address = ""
		inPacketsStr = fields[3]
		inFailStr = fields[4]
		outPacketsStr = fields[5]
		outFailStr = fields[6]
		collsStr = fields[7]
	} else {
		address = fields[3]
		inPacketsStr = fields[4]
		inFailStr = fields[5]
		outPacketsStr = fields[6]
		outFailStr = fields[7]
		collsStr = fields[8]
	}

	inPackets, err := strconv.Atoi(inPacketsStr)
	if err != nil {
		return nil, err
	}

	inFail, err := strconv.Atoi(inFailStr)
	if err != nil {
		return nil, err
	}

	outPackets, err := strconv.Atoi(outPacketsStr)
	if err != nil {
		return nil, err
	}

	outFail, err := strconv.Atoi(outFailStr)
	if err != nil {
		return nil, err
	}

	colls, err := strconv.Atoi(collsStr)
	if err != nil {
		return nil, err
	}

	nif := &netstatInterface{}

	nif.Name = name
	nif.Mtu = mtu
	nif.Network = network
	nif.Address = address
	nif.InPackets = inPackets
	nif.InFail = inFail
	nif.OutPackets = outPackets
	nif.OutFail = outFail
	nif.Colls = colls

	return nif, nil
}

func netstatInterfaces() ([]*netstatInterface, error) {
	outBytes, err := exec.Command("netstat", "-i", "-n").Output()
	if err != nil {
		return nil, err
	}

	out := string(outBytes)
	lines := strings.Split(out, "\n")

	var interfaces []*netstatInterface

	for _, line := range lines[1:] {
		if line == "" {
			continue
		}

		iface, err := genNetstatInterface(line)
		if err != nil {
			fmt.Println(err)
			continue
		}
		interfaces = append(interfaces, iface)
	}

	return interfaces, nil
}
