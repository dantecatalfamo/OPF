package main

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

type WireguardPeer struct {
	PublicKey     string   `json:"publicKey"`
	Endpoint      string   `json:"endpoint"`
	Transmitted   int      `json:"transmitted"`
	Received      int      `json:"received"`
	LastHandshake int      `json:"lastHandshake"`
	AllowedIPs    []string `json:"allowedIPs"`
}

type WireguardInterface struct {
	Port int `json:"port"`
	PublicKey string `json:"publicKey"`
}

func genWireguardPeer(lines []string) (*WireguardPeer, error) {
	return nil, nil
}

func genWireguardInterface(lines []string) (*WireguardInterface, error) {
	return nil, nil
}

func GetWireguardInterfaces() ([]*WireguardInterface, error) {
	outBytes, err := exec.Command("ifconfig", "wg")
	if err != nil {
		return nil, fmt.Errorf("Failed to get wireguard interfaces: %w", err)
	}

	var interfaces []*WireguardInterface

	outString := string(outBytes)
	outLines := strings.Split(outString, "\n")

	groups := groupIndent(outLines)

	for _, group := range groups {
		iface, err := genWireguardInterface(group)
	}
	return nil, nil
}
