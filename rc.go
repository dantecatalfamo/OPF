package main

import (
	"strings"
	"os/exec"
)

func rcAll() ([]string, error) {
	outBytes, err := exec.Command("rcctl", "ls", "all").Output()
	if err != nil {
		return nil, err
	}

	out := string(outBytes)
	lines := strings.Split(out, "\n")
	return lines, nil
}

func rcOn() ([]string, error) {
	outBytes, err := exec.Command("rcctl", "ls", "on").Output()
	if err != nil {
		return nil, err
	}

	out := string(outBytes)
	lines := strings.Split(out, "\n")
	return lines, nil
}

func rcStarted() ([]string, error) {
	outBytes, err := exec.Command("rcctl", "ls", "started").Output()
	if err != nil {
		return nil, err
	}

	out := string(outBytes)
	lines := strings.Split(out, "\n")
	return lines, nil
}
