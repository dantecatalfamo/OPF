package main

import (
	"os/exec"
	"strconv"
	"strings"
)

type CpuStates struct {
	User      int
	Nice      int
	Sys       int
	Spin      int
	Interrupt int
	Idle      int
}

const (
	CP_USER = iota
	CP_NICE
	CP_SYS
	CP_SPIN
	CP_INTR
	CP_IDLE
)

func GetCpuStates() (*CpuStates, error) {
	outBytes, err := exec.Command("sysctl", "kern.cp_time").Output()
	if err != nil {
		return nil, err
	}
	output := strings.Trim(string(outBytes), "\n")
	value := strings.Split(output, "=")[1]
	states := strings.Split(value, ",")
	user, err := strconv.Atoi(states[CP_USER])
	if err != nil {
		return nil, err
	}
	nice, err := strconv.Atoi(states[CP_NICE])
	if err != nil {
		return nil, err
	}
	sys, err := strconv.Atoi(states[CP_SYS])
	if err != nil {
		return nil, err
	}
	spin, err := strconv.Atoi(states[CP_SYS])
	if err != nil {
		return nil, err
	}
	intr, err := strconv.Atoi(states[CP_INTR])
	if err != nil {
		return nil, err
	}
	idle, err := strconv.Atoi(states[CP_IDLE])
	if err != nil {
		return nil, err
	}

	cpu := &CpuStates{}
	cpu.User = user
	cpu.Nice = nice
	cpu.Sys = sys
	cpu.Spin = spin
	cpu.Interrupt = intr
	cpu.Idle = idle

	return cpu, nil
}
