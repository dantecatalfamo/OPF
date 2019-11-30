package main

import (
	"os/exec"
	"strconv"
	"strings"
)

type SwapDevice struct {
	Device    string `json:"device"`
	Blocks    int    `json:"blocks"`
	Used      int    `json:"used"`
	Available int    `json:"available"`
	Capacity  int    `json:"capacity"`
	Priority  int    `json:"priority"`
}

type SwapUsage struct {
	BlockSize int           `json:"blockSize"`
	Devices   []*SwapDevice `json:"devices"`
}

func genSwapDevice(line string) (*SwapDevice, error) {
	fields := strings.Fields(line)
	device := fields[0]
	blocksStr := fields[1]
	blocks, err := strconv.Atoi(blocksStr)
	if err != nil {
		return nil, err
	}

	usedStr := fields[2]
	used, err := strconv.Atoi(usedStr)
	if err != nil {
		return nil, err
	}

	availStr := fields[3]
	avail, err := strconv.Atoi(availStr)
	if err != nil {
		return nil, err
	}

	capacityStr := strings.TrimRight(fields[4], "%")
	capacity, err := strconv.Atoi(capacityStr)
	if err != nil {
		return nil, err
	}

	priorityStr := fields[5]
	priority, err := strconv.Atoi(priorityStr)
	if err != nil {
		return nil, err
	}

	swapdev := &SwapDevice{}

	swapdev.Device = device
	swapdev.Blocks = blocks
	swapdev.Used = used
	swapdev.Available = avail
	swapdev.Capacity = capacity
	swapdev.Priority = priority

	return swapdev, nil
}

func GetSwapUsage() (*SwapUsage, error) {
	outBytes, err := exec.Command("swapctl", "-l").Output()
	if err != nil {
		return nil, err
	}

	out := string(outBytes)
	lines := strings.Split(out, "\n")
	lines = lines[:len(lines)-1]

	titleLine := lines[0]
	titleFields := strings.Fields(titleLine)
	blockSizeStr := strings.Split(titleFields[1], "-")[0]
	blockSize, err := strconv.Atoi(blockSizeStr)
	if err != nil {
		return nil, err
	}

	var swapDevices []*SwapDevice
	for _, line := range lines[1:] {
		swapdev, err := genSwapDevice(line)
		if err != nil {
			return nil, err
		}
		swapDevices = append(swapDevices, swapdev)
	}

	swapUsg := &SwapUsage{}

	swapUsg.BlockSize = blockSize
	swapUsg.Devices = swapDevices

	return swapUsg, nil
}
