package main

import (
	"fmt"
	"io/ioutil"
	"os/exec"
)

func GetDmesg() ([]byte, error) {
	dmesg, err := exec.Command("dmesg").Output()
	if err != nil {
		return nil, fmt.Errorf("Failed to fetch dmesg: %w", err)
	}
	return dmesg, nil
}

func GetLogMessages() ([]byte, error) {
	messages, err := ioutil.ReadFile("/var/log/messages")
	if err != nil {
		return nil, fmt.Errorf("Failed to read /var/log/messages: %w", err)
	}
	return messages, nil
}

func GetLogDaemon() ([]byte, error) {
	daemon, err := ioutil.ReadFile("/var/log/daemon")
	if err != nil {
		return nil, fmt.Errorf("Failed to read /var/log/daemon: %w", err)
	}
	return daemon, nil
}

func GetLogAuthlog() ([]byte, error) {
	authlog, err := ioutil.ReadFile("/var/log/authlog")
	if err != nil {
		return nil, fmt.Errorf("Failed to read /var/log/authlog: %w", err)
	}
	return authlog, nil
}
