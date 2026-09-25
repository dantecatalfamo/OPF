package main

import "strconv"

type RAM struct {
	Total  int `json:"total"`
	Active int `json:"active"`
	Free   int `json:"free"`
}

// GetRAM returns a RAM struct with values in megabytes
func GetRAM() (*RAM, error) {
	vmstat, err := GetVmstat()
	if err != nil {
		return nil, err
	}

	hardware, err := GetHardware()
	if err != nil {
		return nil, err
	}

	totalRam := hardware.UserMemory / 1024 / 1024 // To megabytes

	activeRamRunes := []rune(vmstat.Memory.Active) // remove "M" at end
	activeRamRunes = activeRamRunes[:len(activeRamRunes)-1]
	activeRam, err := strconv.Atoi(string(activeRamRunes))
	if err != nil {
		return nil, err
	}

	freeRamRunes := []rune(vmstat.Memory.Free)
	freeRamRunes = freeRamRunes[:len(freeRamRunes)-1] // remove "M" at end
	freeRam, err := strconv.Atoi(string(freeRamRunes))
	if err != nil {
		return nil, err
	}

	ram := &RAM{}
	ram.Total = totalRam
	ram.Active = activeRam
	ram.Free = freeRam

	return ram, nil
}
