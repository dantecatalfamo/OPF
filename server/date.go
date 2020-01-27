package main

import "os/exec"

func GetDate() (string, error) {
	outBytes, err := exec.Command("date").Output()
	if err != nil {
		return "", err
	}
	output := string(outBytes[:len(outBytes)-1]) // remove newline
	return output, nil
}
