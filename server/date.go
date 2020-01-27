package main

import (
	"os/exec"
	"strings"
)

func GetDate() (string, error) {
	outBytes, err := exec.Command("date").Output()
	if err != nil {
		return "", err
	}
	output := string(outBytes)
	output = strings.TrimRight(output, "\n")
	return output, nil
}
