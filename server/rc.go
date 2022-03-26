package main

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

func GetRcAll() ([]string, error) {
	outBytes, err := exec.Command("rcctl", "ls", "all").Output()
	if err != nil {
		return nil, fmt.Errorf("Unable to list all services: %w", err)
	}

	out := string(outBytes)
	lines := strings.Split(out, "\n")
	return lines[:len(lines)-1], nil
}

func GetRcOn() ([]string, error) {
	outBytes, err := exec.Command("rcctl", "ls", "on").Output()
	if err != nil {
		return nil, fmt.Errorf("Unable to list enabled services: %w", err)
	}

	out := string(outBytes)
	lines := strings.Split(out, "\n")
	return lines[:len(lines)-1], nil
}

func GetRcStarted() ([]string, error) {
	outBytes, err := exec.Command("rcctl", "ls", "started").Output()
	if err != nil {
		return nil, fmt.Errorf("Unable to list running services: %w", err)
	}

	out := string(outBytes)
	lines := strings.Split(out, "\n")
	return lines[:len(lines)-1], nil
}

type RcService struct {
	Name    string `json:"name"`
	Class   string `json:"class"`
	Enabled bool   `json:"enabled"`
	Flags   string `json:"flags"`
	Logger  string `json:"logger"`
	Rtable  int    `json:"rtable"`
	Timeout int    `json:"timeout"`
	User    string `json:"user"`
}

func GetRcService(service string) (*RcService, error) {
	outBytes, err := exec.Command("rcctl", "get", service).Output()
	var exitCode int
	if err != nil {
		exiterr, ok := err.(*exec.ExitError)
		exitCode = exiterr.ExitCode()
		if !ok || exitCode != 1 {
			return nil, fmt.Errorf("rcctl get %s error: %w", service, err)
		}
	}

	out := string(outBytes)
	lines := strings.Split(out, "\n")
	lines = lines[:len(lines)-1]

	// special service
	if len(lines) == 1 {
		flags := strings.Split(lines[0], "=")[1]
		enabled := exitCode == 0
		srv := &RcService{}
		srv.Name = service
		srv.Enabled = enabled
		srv.Flags = flags
		return srv, nil
	}

	values := make(map[string]string)
	for _, line := range lines {
		kv := strings.SplitN(line, "_", 2)[1]
		key_value := strings.SplitN(kv, "=", 2)
		key := key_value[0]
		value := key_value[1]
		values[key] = value
	}

	class := values["class"]
	flags := values["flags"]
	logger := values["logger"]
	enabled := exitCode == 0
	rtable, err := strconv.Atoi(values["rtable"])
	if err != nil {
		return nil, fmt.Errorf("Invalid rc rtable value: %w", err)
	}

	timeout, err := strconv.Atoi(values["timeout"])
	if err != nil {
		return nil, fmt.Errorf("Invalid rc timeout: %w", err)
	}

	user := values["user"]

	srv := &RcService{}

	srv.Name = service
	srv.Class = class
	srv.Enabled = enabled
	srv.Flags = flags
	srv.Logger = logger
	srv.Rtable = rtable
	srv.Timeout = timeout
	srv.User = user

	return srv, nil
}

func GetRcServiceFlags(service string) (string, error) {
	srv, err := GetRcService(service)
	if err != nil {
		return "", err
	}

	return srv.Flags, nil
}

func SetRcServiceFlags(service string, flags string) error {
	err := exec.Command("rcctl", "set", service, "flags", flags).Run()
	if err != nil {
		return fmt.Errorf("Unable to set service %s flag %s: %w", service, flags, err)
	}
	return nil
}

func GetRcServiceStarted(service string) (bool, error) {
	err := exec.Command("rcctl", "check", service).Run()
	if err == nil {
		return true, nil
	}

	exiterr, ok := err.(*exec.ExitError)
	if ok && exiterr.ExitCode() == 1 {
		return false, nil
	}

	return false, err
}

func GetRcServiceEnabled(service string) (bool, error) {
	srv, err := GetRcService(service)
	if err != nil {
		return false, nil
	}

	return srv.Enabled, nil
}

func SetRcServiceStarted(service string, started bool) error {
	if started == true {
		err := exec.Command("rcctl", "-f", "start", service).Run()
		if err != nil {
			return fmt.Errorf("Unable to start service %s: %w", service, err)
		}
		return nil
	} else {
		err := exec.Command("rcctl", "stop", service).Run()
		if err != nil {
			return fmt.Errorf("Unable to stop service %s: %w", service, err)
		}
		return nil
	}
}

func SetRcServiceEnabled(service string, enabled bool) error {
	if enabled == true {
		err := exec.Command("rcctl", "enable", service).Run()
		if err != nil {
			return fmt.Errorf("Unable to enable service %s: %w", service, err)
		}
		return nil
	} else {
		err := exec.Command("rcctl", "disable", service).Run()
		if err != nil {
			return fmt.Errorf("Unable to disable service %s: %w", service, err)
		}
		return nil
	}
}
