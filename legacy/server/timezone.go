package main

import (
	"os/exec"
	"strings"
)

func GetTimezone() (string, error) {
	outBytes, err := exec.Command("date", "+%z").Output()
	if err != nil {
		return "", err
	}

	tz := string(outBytes)
	tz = strings.TrimRight(tz, "\n")
	return tz, nil
}
