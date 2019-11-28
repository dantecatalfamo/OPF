package main

import (
	"os/exec"
	"strconv"
	"strings"
)

type SwapDevice struct {
	Device string
	Blocks int
	Used int
	Available int
	Capacity int
	Priority int
}

type SwapUsage struct {
	BlockSize int
	Devices []*SwapDevice
}
