package main

import (
	"os/exec"
	"strconv"
	"strings"
)

type DiskUsageFilesystem struct {
	Filesystem string `json:"filesystem"`
	Blocks     int    `json:"blocks"`
	Used       int    `json:"used"`
	Available  int    `json:"available"`
	Capacity   int    `json:"capacity"`
	MountPoint string `json:"mountPoint"`
}

type DiskUsage struct {
	BlockSize   int                    `json:"blockSize"`
	Filesystems []*DiskUsageFilesystem `json:"filesystems"`
}

func genDiskUsageLine(line string) (*DiskUsageFilesystem, error) {
	fields := strings.Fields(line)
	filesystem := fields[0]
	blocks, err := strconv.Atoi(fields[1])
	if err != nil {
		return nil, err
	}

	used, err := strconv.Atoi(fields[2])
	if err != nil {
		return nil, err
	}

	available, err := strconv.Atoi(fields[3])
	if err != nil {
		return nil, err
	}

	capStr := strings.TrimRight(fields[4], "%")
	capacity, err := strconv.Atoi(capStr)
	if err != nil {
		return nil, err
	}

	mountPoint := fields[5]

	fs := &DiskUsageFilesystem{}

	fs.Filesystem = filesystem
	fs.Blocks = blocks
	fs.Used = used
	fs.Available = available
	fs.Capacity = capacity
	fs.MountPoint = mountPoint

	return fs, nil
}

func GetDiskUsage() (*DiskUsage, error) {
	outBytes, err := exec.Command("df", "-P").Output()
	if err != nil {
		return nil, err
	}

	out := string(outBytes)
	lines := strings.Split(out, "\n")
	titleLine := strings.Fields(lines[0])
	blockSizeStr := strings.Replace(titleLine[1], "-blocks", "", 1)
	blockSize, err := strconv.Atoi(blockSizeStr)
	if err != nil {
		return nil, err
	}

	var filesystems []*DiskUsageFilesystem
	fsLines := lines[1 : len(lines)-1]
	for _, line := range fsLines {
		fs, err := genDiskUsageLine(line)
		if err != nil {
			return nil, err
		}
		filesystems = append(filesystems, fs)
	}

	df := &DiskUsage{}

	df.BlockSize = blockSize
	df.Filesystems = filesystems

	return df, nil
}
