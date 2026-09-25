package main

import (
	"os/exec"
	"strconv"
	"strings"
)

func GetLoadAvg() ([]float64, error) {
	outBytes, err := exec.Command("sysctl", "vm.loadavg").Output()
	if err != nil {
		return []float64{}, err
	}
	output := string(outBytes)
	output = strings.TrimRight(output, "\n")
	value := strings.Split(output, "=")[1]
	loadStrings := strings.Fields(value)
	oneMin, err := strconv.ParseFloat(loadStrings[0], 64)
	if err != nil {
		return []float64{}, err
	}
	fiveMin, err := strconv.ParseFloat(loadStrings[1], 64)
	if err != nil {
		return []float64{}, err
	}
	fifteenMin, err := strconv.ParseFloat(loadStrings[2], 64)
	if err != nil {
		return []float64{}, err
	}
	return []float64{oneMin, fiveMin, fifteenMin}, nil
}
