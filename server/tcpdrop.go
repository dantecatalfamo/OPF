package main

import (
	"os/exec"
	"strconv"
)

func tcpdrop(localIP string, localPort int, remoteIP string, remotePort int) error {
	localPortStr := strconv.Itoa(localPort)
	remotePortStr := strconv.Itoa(remotePort)
	err := exec.Command("tcpdrop", localIP, localPortStr, remoteIP, remotePortStr).Run()
	if err != nil {
		return err
	}
	return nil

}
