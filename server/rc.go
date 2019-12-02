package main

import (
	"os/exec"
	"strconv"
	"strings"
)

func GetRcAll() ([]string, error) {
	outBytes, err := exec.Command("rcctl", "ls", "all").Output()
	if err != nil {
		return nil, err
	}

	out := string(outBytes)
	lines := strings.Split(out, "\n")
	return lines[:len(lines)-1], nil
}

func GetRcOn() ([]string, error) {
	outBytes, err := exec.Command("rcctl", "ls", "on").Output()
	if err != nil {
		return nil, err
	}

	out := string(outBytes)
	lines := strings.Split(out, "\n")
	return lines[:len(lines)-1], nil
}

func GetRcStarted() ([]string, error) {
	outBytes, err := exec.Command("rcctl", "ls", "started").Output()
	if err != nil {
		return nil, err
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
	Rtable  int    `json: rtable"`
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
			return nil, err
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

	class := strings.Split(lines[0], "=")[1]
	flags := strings.Split(lines[1], "=")[1]
	enabled := exitCode == 0
	rtableStr := strings.Split(lines[2], "=")[1]
	rtable, err := strconv.Atoi(rtableStr)
	if err != nil {
		return nil, err
	}

	timeoutStr := strings.Split(lines[3], "=")[1]
	timeout, err := strconv.Atoi(timeoutStr)
	if err != nil {
		return nil, err
	}

	user := strings.Split(lines[4], "=")[1]

	srv := &RcService{}

	srv.Name = service
	srv.Class = class
	srv.Enabled = enabled
	srv.Flags = flags
	srv.Rtable = rtable
	srv.Timeout = timeout
	srv.User = user

	return srv, nil
}
