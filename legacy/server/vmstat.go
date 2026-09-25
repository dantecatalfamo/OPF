package main

import (
	"os/exec"
	"strconv"
	"strings"
)

type VmstatDisk struct {
	Name      string `json:"name"`
	Transfers int    `json:"transfers"`
}

type Vmstat struct {
	Procs struct {
		Running  int `json:"running"`
		Sleeping int `json:"sleeping"`
	} `json:"procs"`
	Memory struct {
		Active string `json:"active"`
		Free   string `json:"free"`
	} `json:"memory"`
	Page struct {
		Faults   int `json:"faults"`
		Relcaims int `json:"reclaims"`
		PagedIn  int `json:"pagedIn"`
		PagedOut int `json:"pagedOut"`
		Freed    int `json:"freed"`
		Scanned  int `json:"scanned"`
	} `json:"page"`
	Disks []VmstatDisk `json:"disks"`
	Traps struct {
		Interrupts    int `json:"interrupts"`
		SystemCalls   int `json:"systemCalls"`
		ContextSwitch int `json:"contextSwitch"`
	} `json:"traps"`
	CPU struct {
		User   int `json:"user"`
		System int `json:"system"`
		Idle   int `json:"idle"`
	} `json:"cpu"`
}

func GetVmstat() (*Vmstat, error) {
	outBytes, err := exec.Command("vmstat").Output()
	if err != nil {
		return nil, err
	}

	var disks []VmstatDisk
	out := string(outBytes)
	lines := strings.Split(out, "\n")
	fields := strings.Fields(lines[2])
	nDisks := len(fields) - 16
	afterDisks := 10 + nDisks

	procsRunning, err := strconv.Atoi(fields[0])
	if err != nil {
		return nil, err
	}

	procsSleeping, err := strconv.Atoi(fields[1])
	if err != nil {
		return nil, err
	}

	memoryActive := fields[2]
	memoryFree := fields[3]
	pageFaults, err := strconv.Atoi(fields[4])
	if err != nil {
		return nil, err
	}

	pageReclaims, err := strconv.Atoi(fields[5])
	if err != nil {
		return nil, err
	}

	pageIn, err := strconv.Atoi(fields[6])
	if err != nil {
		return nil, err
	}

	pageOut, err := strconv.Atoi(fields[7])
	if err != nil {
		return nil, err
	}

	pageFreed, err := strconv.Atoi(fields[8])
	if err != nil {
		return nil, err
	}

	pageScanned, err := strconv.Atoi(fields[9])
	if err != nil {
		return nil, err
	}

	titleLine := lines[1]
	diskNames := strings.Fields(titleLine)[10:afterDisks]
	diskTransfers := fields[10 : 10+nDisks]
	for i, name := range diskNames {
		transfers, err := strconv.Atoi(diskTransfers[i])
		if err != nil {
			return nil, err
		}
		disk := VmstatDisk{
			Name:      name,
			Transfers: transfers,
		}
		disks = append(disks, disk)
	}

	trapInterrupts, err := strconv.Atoi(fields[afterDisks])
	if err != nil {
		return nil, err
	}

	trapSystemCalls, err := strconv.Atoi(fields[afterDisks+1])
	if err != nil {
		return nil, err
	}

	trapContextSwitch, err := strconv.Atoi(fields[afterDisks+2])
	if err != nil {
		return nil, err
	}

	cpuUser, err := strconv.Atoi(fields[afterDisks+3])
	if err != nil {
		return nil, err
	}

	cpuSystem, err := strconv.Atoi(fields[afterDisks+4])
	if err != nil {
		return nil, err
	}

	cpuIdle, err := strconv.Atoi(fields[afterDisks+5])
	if err != nil {
		return nil, err
	}

	vmst := &Vmstat{}

	vmst.Procs.Running = procsRunning
	vmst.Procs.Sleeping = procsSleeping
	vmst.Memory.Active = memoryActive
	vmst.Memory.Free = memoryFree
	vmst.Page.Faults = pageFaults
	vmst.Page.Relcaims = pageReclaims
	vmst.Page.PagedIn = pageIn
	vmst.Page.PagedOut = pageOut
	vmst.Page.Freed = pageFreed
	vmst.Page.Scanned = pageScanned
	vmst.Disks = disks
	vmst.Traps.Interrupts = trapInterrupts
	vmst.Traps.SystemCalls = trapSystemCalls
	vmst.Traps.ContextSwitch = trapContextSwitch
	vmst.CPU.User = cpuUser
	vmst.CPU.System = cpuSystem
	vmst.CPU.Idle = cpuIdle

	return vmst, nil
}
