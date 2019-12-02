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
	Class string `json:"class"`
	Enabled bool `json:"enabled"`
	Flags string `json:"flags"`
	Rtable int `json: rtable"`
	Timeout int `json:"timeout"`
	User string `json:"user"`
}

func GetRcService(service string) (*RcService, error) {
	outBytes, err := exec.Command("rcctl", "get", service).Output()
	if err != nil {
		return nil, err
	}

	out := string(outBytes)
	lines := strings.Split(out, "\n")
	lines = lines[:len(lines)-1]

	class := strings.Split(lines[0], "=")[1]
	flags := strings.Split(lines[1], "=")[1]
	enabled := flags != "NO"
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

	srv.Class = class
	srv.Enabled = enabled
	srv.Flags = flags
	srv.Rtable = rtable
	srv.Timeout = timeout
	srv.User = user

	return srv, nil
}
