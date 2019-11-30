package main

import (
	"os/exec"
	"strconv"
	"strings"
)

type HardwareDisk struct {
	Name string `json:"name"`
	DUID string `json:"duid"`
}

type HardwareSensor struct {
	Path  []string `json:"path"`
	Value string   `json:"value"`
}

type hardwareLine struct {
	Path  []string
	Value string
}

type Hardware struct {
	Machine        string            `json:"machine"`
	Model          string            `json:"model"`
	NCPU           int               `json:"ncpu"`
	ByteOrder      int               `json:"byteOrder"`
	PageSize       int               `json:"pageSize"`
	Disks          []*HardwareDisk   `json:"disks"`
	DiskCount      int               `json:"diskCount"`
	Sensors        []*HardwareSensor `json:"sensors"`
	CPUSpeed       int               `json:"cpuSpeed"`
	Vendor         string            `json:"vendor"`
	Product        string            `json:"product"`
	Version        string            `json:"version"`
	SerialNumber   string            `json:"serialNumber"`
	UUID           string            `json:"uuid"`
	PhysicalMemory int               `json:"physMem"`
	UserMemory     int               `json:"userMem"`
	NCPUFound      int               `json:"ncpuFound"`
	AllowPowerDown int               `json:"allowPowerDown"`
	SMT            int               `json:"smt"`
	NCPUOnline     int               `json:"ncpuOnline"`
}

func getHardwareLines(lines []string, key string) []hardwareLine {
	var out []hardwareLine
	for _, line := range lines {
		lineSplit := strings.SplitN(line, "=", 2)
		path := lineSplit[0]
		value := lineSplit[1]
		if strings.Contains(path, key) {
			split := strings.Split(path, ".")
			hwl := hardwareLine{
				Path:  split,
				Value: value,
			}
			out = append(out, hwl)
		}
	}
	return out
}

func getHardwareLine(lines []string, key string) hardwareLine {
	hwl := getHardwareLines(lines, key)
	if len(hwl) < 1 {
		return hardwareLine{}
	}
	return hwl[0]
}

func hardware() (*Hardware, error) {
	outBytes, err := exec.Command("sysctl", "hw").Output()
	if err != nil {
		return nil, err
	}

	out := string(outBytes)
	lines := strings.Split(out, "\n")
	lines = lines[:len(lines)-1]

	machine := getHardwareLine(lines, "hw.machine").Value
	model := getHardwareLine(lines, "hw.model").Value
	ncpuStr := getHardwareLine(lines, "hw.ncpu").Value
	ncpu, err := strconv.Atoi(ncpuStr)
	if err != nil {
		return nil, err
	}

	byteOrderStr := getHardwareLine(lines, "hw.byteorder").Value
	byteOrder, err := strconv.Atoi(byteOrderStr)
	if err != nil {
		return nil, err
	}

	pageSize, err := strconv.Atoi(getHardwareLine(lines, "hw.pagesize").Value)
	if err != nil {
		return nil, err
	}

	var disks []*HardwareDisk
	diskLine := getHardwareLine(lines, "hw.disknames")
	disksDUID := strings.Split(diskLine.Value, ",")
	for _, disk := range disksDUID {
		diskSplit := strings.Split(disk, ":")
		hwd := &HardwareDisk{}
		hwd.Name = diskSplit[0]
		hwd.DUID = diskSplit[1]
		disks = append(disks, hwd)
	}

	diskCountStr := getHardwareLine(lines, "hw.diskcount").Value
	diskCount, err := strconv.Atoi(diskCountStr)
	if err != nil {
		return nil, err
	}

	var sensors []*HardwareSensor
	sensorLines := getHardwareLines(lines, "hw.sensors")
	for _, sensor := range sensorLines {
		value := sensor.Value
		snsr := &HardwareSensor{}
		snsr.Path = sensor.Path[2:]
		snsr.Value = value
		sensors = append(sensors, snsr)
	}

	cpuSpeedStr := getHardwareLine(lines, "hw.cpuspeed").Value
	cpuSpeed, err := strconv.Atoi(cpuSpeedStr)
	if err != nil {
		return nil, err
	}

	vendor := getHardwareLine(lines, "hw.vendor").Value
	product := getHardwareLine(lines, "hw.product").Value
	version := getHardwareLine(lines, "hw.version").Value
	serialNumber := getHardwareLine(lines, "hw.serialno").Value
	uuid := getHardwareLine(lines, "hw.uuid").Value
	physMemStr := getHardwareLine(lines, "hw.physmem").Value
	physMem, err := strconv.Atoi(physMemStr)
	if err != nil {
		return nil, err
	}

	userMemStr := getHardwareLine(lines, "hw.usermem").Value
	userMem, err := strconv.Atoi(userMemStr)
	if err != nil {
		return nil, err
	}

	nCpuFoundStr := getHardwareLine(lines, "hw.ncpufound").Value
	nCpuFound, err := strconv.Atoi(nCpuFoundStr)
	if err != nil {
		return nil, err
	}

	allowPowerDownStr := getHardwareLine(lines, "hw.allowpowerdown").Value
	allowPowerDown, err := strconv.Atoi(allowPowerDownStr)
	if err != nil {
		return nil, err
	}

	smtStr := getHardwareLine(lines, "hw.smt").Value
	smt, err := strconv.Atoi(smtStr)
	if err != nil {
		return nil, err
	}

	nCpuOnlineStr := getHardwareLine(lines, "hw.ncpuonline").Value
	nCpuOnline, err := strconv.Atoi(nCpuOnlineStr)
	if err != nil {
		return nil, err
	}

	hw := &Hardware{}

	hw.Machine = machine
	hw.Model = model
	hw.NCPU = ncpu
	hw.ByteOrder = byteOrder
	hw.PageSize = pageSize
	hw.Disks = disks
	hw.DiskCount = diskCount
	hw.Sensors = sensors
	hw.CPUSpeed = cpuSpeed
	hw.Vendor = vendor
	hw.Product = product
	hw.Version = version
	hw.SerialNumber = serialNumber
	hw.UUID = uuid
	hw.PhysicalMemory = physMem
	hw.UserMemory = userMem
	hw.NCPUFound = nCpuFound
	hw.AllowPowerDown = allowPowerDown
	hw.SMT = smt
	hw.NCPUOnline = nCpuOnline

	return hw, nil
}
