package main

import (
	"strings"
	"strconv"
)

func groupIndent(lines []string) [][]string {
	var group []string
	var groups [][]string

	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		firstChar := []rune(line)[0]
		if firstChar == ' ' || firstChar == '\t' {
			group = append(group, line)
		} else {
			if len(group) > 0 {
				groups = append(groups, group)
			}
			group = nil
			group = append(group, line)
		}
	}

	groups = append(groups, group)

	return groups
}

func splitIp(ip string) (string, int, error) {
	if strings.Contains(ip, ".") {
		ipSplit := strings.Split(ip, ":")
		port, err := strconv.Atoi(ipSplit[1])
		if err != nil {
			return "", 0, err
		}
		return ipSplit[0], port, nil
	} else {
		ipSplit := strings.Split(ip, "[")
		portStr := strings.Trim(ipSplit[1], "]")
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return "", 0, err
		}
		return ipSplit[0], port, nil
	}
}
