package main

import "os/exec"

func GetHostname() (string, error) {
	output, err := exec.Command("hostname").Output()
	if err != nil {
		return "", err
	}
	hostname := string(output[:len(output)-1]) // remove newline
	return hostname, nil
}
