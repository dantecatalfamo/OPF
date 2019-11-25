package main

import (
	"os/exec"
	"strconv"
	"strings"
)

type Vmstat struct {
	Procs struct {
		Running  int `json:"running"`
		Sleeping int `json:"sleeping"`
	} `json:"procs"`
	Memory struct {
		Active int `json:"active"`
		Free   int `json:"free"`
	} `json:"memory"`
	Page struct {
		Faults   int `json:"faults"`
		Relcaims int `json:"reclaims"`
		PagedOut int `json:"pagedOut"`
		PagedIn  int `json:"pagedIn"`
		Freed    int `json:"freed"`
		Scanned  int `json:"scanned"`
	} `json:"page"`
	Disks []struct {
		Name     string `json:"name"`
		Tranfers int    `json:"transfers"`
	} `json:"disks"`
	Traps struct {
		Interrupts    int `json:"interrupts"`
		SystemCalls   int `json:"systemCalls"`
		ContextSwitch int `json:"contextSwitch"`
	} `json:"traps"`
	CPU struct {
		User   int `json:"user"`
		System int `json:"system"`
		Idle   int `json:"idle"`
	} `json:"cpu"`
}
