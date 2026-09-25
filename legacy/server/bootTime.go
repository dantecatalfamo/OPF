package main

import (
	"os/exec"
	"strings"
)

func GetBootTime() (string, error) {
	outBytes, err := exec.Command("sysctl", "kern.boottime").Output()
	if err != nil {
		return "", err
	}
	output := string(outBytes)
	output = strings.TrimRight(output, "\n")
	bootTime := strings.Split(output, "=")[1]

	timeZone, err := GetTimezone()
	if err != nil {
		return "", err
	}

	fullTime := strings.Join([]string{bootTime, timeZone}, " ")

	return fullTime, nil
}
