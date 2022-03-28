package main

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

type InterfaceAddress struct {
	Family    string `json:"family"`
	Address   string `json:"address"`
	Netmask   string `json:"netmask"`
	Broadcast string `json:"broadcast"`
}

type WireguardPeer struct {
	PublicKey       string   `json:"publicKey"`
	EndpointAddress string   `json:"endpointAddress"`
	EndpointPort    int      `json:"endpointPort"`
	Transmitted     int      `json:"transmitted"`
	Received        int      `json:"received"`
	LastHandshake   int      `json:"lastHandshake"`
	AllowedIPs      []string `json:"allowedIPs"`
}

type WireguardInterface struct {
	Name      string              `json:"name"`
	Port      int                 `json:"port"`
	PublicKey string              `json:"publicKey"`
	Addresses []*InterfaceAddress `json:"addresses"`
	Flags     string              `json:"flags"`
	MTU       int                 `json:"mtu"`
	Groups    []string            `json:"groups"`
	Peers     []*WireguardPeer    `json:"peers"`
}

func init() {
	prometheus.MustRegister(WireguardPeerCollector{})
}

var (
	wireguardPeerTxDesc = prometheus.NewDesc("opf_wireguard_peer_tx_bytes_total", "Bytes transmitted by a wireguard peer", []string{"interface", "publickey"}, nil)
	wireguardPeerRxDesc = prometheus.NewDesc("opf_wireguard_peer_rx_bytes_total", "Bytes received by a wireguard peer", []string{"interface", "publickey"}, nil)
)

type WireguardPeerCollector struct{}

func (wpc WireguardPeerCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- wireguardPeerTxDesc
	ch <- wireguardPeerRxDesc
}

func (wpc WireguardPeerCollector) Collect(ch chan<- prometheus.Metric) {
	wgs, err := GetWireguardInterfaces()
	if err != nil {
		fmt.Println(err)
	}
	for _, wg := range wgs {
		ifName := wg.Name
		for _, peer := range wg.Peers {
			key := peer.PublicKey
			tx := peer.Transmitted
			rx := peer.Received
			ch <- prometheus.MustNewConstMetric(wireguardPeerTxDesc, prometheus.CounterValue, float64(tx), ifName, key)
			ch <- prometheus.MustNewConstMetric(wireguardPeerRxDesc, prometheus.CounterValue, float64(rx), ifName, key)
		}
	}
}

func genWireguardPeer(lines []string) (*WireguardPeer, error) {
	peer := &WireguardPeer{}
	peer.PublicKey = strings.Fields(lines[0])[1]

	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		switch fields[0] {
		case "wgendpoint":
			peer.EndpointAddress = fields[1]
			port, err := strconv.Atoi(fields[2])
			if err != nil {
				return nil, fmt.Errorf("Could not get wg peer %s endpoint port: %w", peer.PublicKey, err)
			}
			peer.EndpointPort = port
		case "wgaip":
			peer.AllowedIPs = append(peer.AllowedIPs, fields[1])
		case "last": // handshake
			lastHandshake, err := strconv.Atoi(fields[2])
			if err != nil {
				return nil, fmt.Errorf("Could not get wg peer %s last handshake: %s", peer.PublicKey, err)
			}
			peer.LastHandshake = lastHandshake
		case "tx:":
			txStr := strings.Split(fields[1], ",")[0]
			tx, err := strconv.Atoi(txStr)
			if err != nil {
				return nil, fmt.Errorf("Could not get wg peer %s tx: %w", peer.PublicKey, err)
			}
			peer.Transmitted = tx
			rx, err := strconv.Atoi(fields[3])
			if err != nil {
				return nil, fmt.Errorf("Could not get wg peer %s rx: %w", peer.PublicKey, err)
			}
			peer.Received = rx
		}
	}
	return peer, nil
}

func genWireguardInterface(lines []string) (*WireguardInterface, error) {
	iface := &WireguardInterface{}

	ifaceNameSplit := strings.SplitN(lines[0], ":", 2)
	iface.Name = ifaceNameSplit[0]

	flagsSplit := strings.Fields(ifaceNameSplit[1])
	iface.Flags = strings.Split(flagsSplit[0], "=")[1]

	mtu, err := strconv.Atoi(flagsSplit[2])
	if err != nil {
		return nil, fmt.Errorf("Could not retrieve MTU for interface %s: %w", iface.Name, err)
	}
	iface.MTU = mtu

	for idx, line := range lines {
		if idx == 0 || line[1] == '\t' {
			continue // Skip lines inside of 'wgpeer' and first line
		}
		fields := strings.Fields(line)
		switch fields[0] {
		case "wgport":
			wgport, err := strconv.Atoi(fields[1])
			if err != nil {
				return nil, fmt.Errorf("Could not get wgport on interface %s: %w", iface.Name, err)
			}
			iface.Port = wgport
		case "wgpubkey":
			iface.PublicKey = fields[1]
		case "groups:":
			iface.Groups = fields[1:]
		case "inet", "inet6":
			addr := &InterfaceAddress{}
			addr.Family = fields[0]
			addr.Address = fields[1]
			addr.Netmask = fields[3]
			addr.Broadcast = fields[5]
			iface.Addresses = append(iface.Addresses, addr)
		case "wgpeer":
			peerIdx := idx + 1
			for peerIdx < len(lines) {
				if lines[peerIdx][1] == '\t' {
					peerIdx += 1
				} else {
					break
				}
			}
			peer, err := genWireguardPeer(lines[idx:peerIdx])
			if err != nil {
				return nil, err
			}
			iface.Peers = append(iface.Peers, peer)
		}
	}
	return iface, nil
}

func GetWireguardInterfaces() ([]*WireguardInterface, error) {
	outBytes, err := exec.Command("doas", "ifconfig", "wg").Output()
	if err != nil {
		return nil, fmt.Errorf("Failed to get wireguard interfaces: %w", err)
	}

	var interfaces []*WireguardInterface

	outString := string(outBytes)
	outLines := strings.Split(outString, "\n")

	groups := groupIndent(outLines)

	for _, group := range groups {
		iface, err := genWireguardInterface(group)
		if err != nil {
			return nil, err
		}
		interfaces = append(interfaces, iface)
	}
	return interfaces, nil
}
