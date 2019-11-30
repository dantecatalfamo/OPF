package main

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

type PfInterface struct {
	Interface  string `json:"interface"`
	Cleared    string `json:"cleared"`
	References struct {
		States int `json:"states"`
		Rules  int `json:"rules"`
	} `json:"references"`
	In4Pass struct {
		Packets int `json:"packets"`
		Bytes   int `json:"bytes"`
	} `json:"in4pass"`
	In4Block struct {
		Packets int `json:"packets"`
		Bytes   int `json:"bytes"`
	} `json:"in4block"`
	Out4Pass struct {
		Packets int `json:"packets"`
		Bytes   int `json:"bytes"`
	} `json:"out4pass"`
	Out4Block struct {
		Packets int `json:"packets"`
		Bytes   int `json:"bytes"`
	} `json:"out4block"`
	In6Pass struct {
		Packets int `json:"packets"`
		Bytes   int `json:"bytes"`
	} `json:"in6pass"`
	In6Block struct {
		Packets int `json:"packets"`
		Bytes   int `json:"bytes"`
	} `json:"in6block"`
	Out6Pass struct {
		Packets int `json:"packets"`
		Bytes   int `json:"bytes"`
	} `json:"out6pass"`
	Out6Block struct {
		Packets int `json:"packets"`
		Bytes   int `json:"bytes"`
	} `json:"out6block"`
}

func pfInterfaceLine(line string) (int, int, error) {
	fields := strings.Fields(line)
	int1, err := strconv.Atoi(fields[3])
	if err != nil {
		return 0, 0, err
	}
	int2, err := strconv.Atoi(strings.TrimRight(fields[5], "]"))
	if err != nil {
		return 0, 0, err
	}
	return int1, int2, nil
}

func genPfInterface(lines []string) (*PfInterface, error) {
	ifLine := lines[0]
	iface := strings.TrimSpace(ifLine)

	clearLine := strings.Fields(lines[1])
	cleared := strings.Join(clearLine[1:], " ")

	states, rules, err := pfInterfaceLine(lines[2])
	if err != nil {
		return nil, err
	}

	i4pPkt, i4pByte, err := pfInterfaceLine(lines[3])
	if err != nil {
		return nil, err
	}

	i4bPkt, i4bByte, err := pfInterfaceLine(lines[4])
	if err != nil {
		return nil, err
	}

	o4pPkt, o4pByte, err := pfInterfaceLine(lines[5])
	if err != nil {
		return nil, err
	}

	o4bPkt, o4bByte, err := pfInterfaceLine(lines[6])
	if err != nil {
		return nil, err
	}

	i6pPkt, i6pByte, err := pfInterfaceLine(lines[7])
	if err != nil {
		return nil, err
	}

	i6bPkt, i6bByte, err := pfInterfaceLine(lines[8])
	if err != nil {
		return nil, err
	}

	o6pPkt, o6pByte, err := pfInterfaceLine(lines[9])
	if err != nil {
		return nil, err
	}

	o6bPkt, o6bByte, err := pfInterfaceLine(lines[10])
	if err != nil {
		return nil, err
	}

	pfInterface := &PfInterface{}

	pfInterface.Interface = iface
	pfInterface.Cleared = cleared
	pfInterface.References.States = states
	pfInterface.References.Rules = rules
	pfInterface.In4Pass.Packets = i4pPkt
	pfInterface.In4Pass.Bytes = i4pByte
	pfInterface.In4Block.Packets = i4bPkt
	pfInterface.In4Block.Bytes = i4bByte
	pfInterface.Out4Pass.Packets = o4pPkt
	pfInterface.Out4Pass.Bytes = o4pByte
	pfInterface.Out4Block.Packets = o4bPkt
	pfInterface.Out4Block.Bytes = o4bByte
	pfInterface.In6Pass.Packets = i6pPkt
	pfInterface.In6Pass.Bytes = i6pByte
	pfInterface.In6Block.Packets = i6bPkt
	pfInterface.In6Block.Bytes = i6bByte
	pfInterface.Out6Pass.Packets = o6pPkt
	pfInterface.Out6Pass.Bytes = o6pByte
	pfInterface.Out6Block.Packets = o6bPkt
	pfInterface.Out6Block.Bytes = o6bByte

	return pfInterface, nil
}

func GetPfInterfaces() ([]*PfInterface, error) {
	outBytes, err := exec.Command("pfctl", "-vv", "-s", "Interface").Output()
	if err != nil {
		return nil, err
	}

	var interfaces []*PfInterface

	outString := string(outBytes)
	outLines := strings.Split(outString, "\n")

	groups := groupIndent(outLines)

	for _, group := range groups {
		iface, err := genPfInterface(group)
		if err != nil {
			fmt.Println(err)
			continue
		}
		interfaces = append(interfaces, iface)
	}

	return interfaces, nil
}
