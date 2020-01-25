package main

import "os/exec"

// PfKillID kills the PF state entry associated with the unique state
// ID shown by pfctl -s states -vv
func PfKillID(id string) error {
	err := exec.Command("pfctl", "-k", "id", "-k", id).Run()
	if err != nil {
		return err
	}
	return nil
}
