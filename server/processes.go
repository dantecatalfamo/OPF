package main

import (
	"os/exec"
	"strconv"
	"strings"
)

type Process struct {
	User              string   `json:"user"`
	Group             string   `json:"group"`
	PID               int      `json:"pid"`
	ParentPID         int      `json:"parentPid"`
	Stat              []string `json:"stat"`
	PercentCPU        float64  `json:"percentCPU"`
	PercentMemory     float64  `json:"percentMemory"`
	VirtualMemorySize int      `json:"virtualMemorySize"`
	ResidentSetSize   int      `json:"residentSetSize"`
	Nice              int      `json:"nice"`
	Priority          int      `json:"priority"`
	WaitChannel       string   `json:"waitChannel"`
	Elapsed           struct {
		Days int    `json:"days"`
		Time string `json:"hours"`
	} `json:"elapsed"`
	Started  string `json:"started"`
	Time     string `json:"time"`
	Terminal string `json:"terminal"`
	Command  string `json:"command"`
}

func genProcess(line string, tz string) (*Process, error) {
	fields := strings.Fields(line)
	user := fields[0]
	group := fields[1]
	pidStr := fields[2]
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return nil, err
	}

	ppidStr := fields[3]
	ppid, err := strconv.Atoi(ppidStr)
	if err != nil {
		return nil, err
	}

	var stat []string
	statStr := fields[4]
	for _, c := range statStr {
		switch c {
		case 'D':
			stat = append(stat, "uninterruptible")
		case 'I':
			stat = append(stat, "idle")
		case 'R':
			stat = append(stat, "runnable")
		case 'S':
			stat = append(stat, "sleeping")
		case 'T':
			stat = append(stat, "stopped")
		case 'Z':
			stat = append(stat, "zombie")
		case '+':
			stat = append(stat, "foreground")
		case '<':
			stat = append(stat, "raised_priority")
		case '>':
			stat = append(stat, "memory_limit_exceeded")
		case 'E':
			stat = append(stat, "exiting")
		case 'K':
			stat = append(stat, "kernel")
		case 'N':
			stat = append(stat, "reduced_priority")
		case 'p':
			stat = append(stat, "pledged")
		case 's':
			stat = append(stat, "session_leader")
		case 'U':
			stat = append(stat, "unveil_locked")
		case 'u':
			stat = append(stat, "unveil_not_locked")
		case 'V':
			stat = append(stat, "suspended_vfork")
		case 'X':
			stat = append(stat, "debugging")
		}
	}

	pCpuStr := fields[5]
	pCpu, err := strconv.ParseFloat(pCpuStr, 64)
	if err != nil {
		return nil, err
	}

	pMemStr := fields[6]
	pMem, err := strconv.ParseFloat(pMemStr, 64)
	if err != nil {
		return nil, err
	}

	vszStr := fields[7]
	vsz, err := strconv.Atoi(vszStr)
	if err != nil {
		return nil, err
	}

	rssStr := fields[8]
	rss, err := strconv.Atoi(rssStr)
	if err != nil {
		return nil, err
	}

	niceStr := fields[9]
	nice, err := strconv.Atoi(niceStr)
	if err != nil {
		return nil, err
	}

	priStr := fields[10]
	pri, err := strconv.Atoi(priStr)
	if err != nil {
		return nil, err
	}

	wchan := fields[11]

	var elapsedDays int
	var elapsedTime string
	elapsedStr := fields[12]
	elapsedSplit := strings.Split(elapsedStr, "-")
	if len(elapsedSplit) == 1 {
		elapsedTime = elapsedStr
	} else {
		elapsedDays, err = strconv.Atoi(elapsedSplit[0])
		if err != nil {
			return nil, err
		}
		elapsedTime = elapsedSplit[1]
	}

	started := strings.Join(fields[13:18], " ")
	started = started + " " + tz
	time := fields[18]
	terminal := fields[19]
	command := strings.Join(fields[20:], " ")

	proc := &Process{}

	proc.User = user
	proc.Group = group
	proc.PID = pid
	proc.ParentPID = ppid
	proc.Stat = stat
	proc.PercentCPU = pCpu
	proc.PercentMemory = pMem
	proc.VirtualMemorySize = vsz
	proc.ResidentSetSize = rss
	proc.Nice = nice
	proc.Priority = pri
	proc.WaitChannel = wchan
	proc.Elapsed.Days = elapsedDays
	proc.Elapsed.Time = elapsedTime
	proc.Started = started
	proc.Time = time
	proc.Terminal = terminal
	proc.Command = command

	return proc, nil
}

func GetProcesses() ([]*Process, error) {
	outBytes, err := exec.Command("ps", "Aww", "-o", "ruser,rgroup,pid,ppid,state,pcpu,pmem,vsz,rss,nice,pri,wchan,etime,lstart,time,tt,command").Output()
	if err != nil {
		return nil, err
	}

	out := string(outBytes)
	lines := strings.Split(out, "\n")
	lines = lines[:len(lines)-1]

	timeZone, err := GetTimezone()
	if err != nil {
		return nil, err
	}

	var procs []*Process
	for _, line := range lines[1:] {
		proc, err := genProcess(line, timeZone)
		if err != nil {
			return nil, err
		}
		procs = append(procs, proc)
	}

	return procs, nil
}
