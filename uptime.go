package main

import (
	"strconv"
	"os/exec"
	"strings"
)

type Uptime struct {
	Time string
	Uptime string
	Users int
	LoadAvg []float64
}

func uptime() (*Uptime, error){
	outBytes, err := exec.Command("uptime").Output()
	if err != nil {
		return nil, err
	}
	out := string(outBytes)
	fields := strings.Fields(out)
	time := fields[0]
	up := strings.TrimRight(strings.Join(fields[2:5], " "), ",")
	users, err := strconv.Atoi(fields[5])
	if err != nil {
		return nil, err
	}
	var loadAvg []float64
	for _, f := range fields[9:] {
		f = strings.TrimRight(f, ",")
		load, err := strconv.ParseFloat(f, 64)
		if err != nil {
			return nil, err
		}
		loadAvg = append(loadAvg, load)
	}

	ut := &Uptime{}

	ut.Time = time
	ut.Uptime = up
	ut.Users = users
	ut.LoadAvg = loadAvg

	return ut, nil
}
