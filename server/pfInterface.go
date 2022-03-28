package main

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

type PfInterface struct {
	Interface  string `json:"interface"`
	Cleared    string `json:"cleared"`
	References struct {
		States int `json:"states"`
		Rules  int `json:"rules"`
	} `json:"references"`
	In4Pass struct {
		Packets int `json:"packets"`
		Bytes   int `json:"bytes"`
	} `json:"in4pass"`
	In4Block struct {
		Packets int `json:"packets"`
		Bytes   int `json:"bytes"`
	} `json:"in4block"`
	Out4Pass struct {
		Packets int `json:"packets"`
		Bytes   int `json:"bytes"`
	} `json:"out4pass"`
	Out4Block struct {
		Packets int `json:"packets"`
		Bytes   int `json:"bytes"`
	} `json:"out4block"`
	In6Pass struct {
		Packets int `json:"packets"`
		Bytes   int `json:"bytes"`
	} `json:"in6pass"`
	In6Block struct {
		Packets int `json:"packets"`
		Bytes   int `json:"bytes"`
	} `json:"in6block"`
	Out6Pass struct {
		Packets int `json:"packets"`
		Bytes   int `json:"bytes"`
	} `json:"out6pass"`
	Out6Block struct {
		Packets int `json:"packets"`
		Bytes   int `json:"bytes"`
	} `json:"out6block"`
}

func init() {
	prometheus.MustRegister(PfInterfaceCollector{})
}

var (
	pfInterfaceStates = prometheus.NewDesc("opf_pf_interface_states", "Number of states currently referencing a PF interface", []string{"interface"}, nil)
	pfInterfaceRules = prometheus.NewDesc("opf_pf_interface_rules", "Number of rules currently referencing a PF interface", []string{"interface"}, nil)
	pfInterfaceInPassPackets = prometheus.NewDesc("opf_pf_interface_in_pass_packets_total", "Number of inbound packets passed by a PF interface", []string{"interface", "family"}, nil)
	pfInterfaceInPassBytes = prometheus.NewDesc("opf_pf_interface_in_pass_bytes_total", "Number of inbound bytes passed by a PF interface", []string{"interface", "family"}, nil)
	pfInterfaceInBlockPackets = prometheus.NewDesc("opf_pf_interface_in_block_packets_total", "Number of inbound packets blocked by a PF interface", []string{"interface", "family"}, nil)
	pfInterfaceInBlockBytes = prometheus.NewDesc("opf_pf_interface_in_block_bytes_total", "Number of inbound bytes blocked by a PF interface", []string{"interface", "family"}, nil)
	pfInterfaceOutPassPackets = prometheus.NewDesc("opf_pf_interface_out_pass_packets_total", "Number of outbound packets passed by a PF interface", []string{"interface", "family"}, nil)
	pfInterfaceOutPassBytes = prometheus.NewDesc("opf_pf_interface_out_pass_bytes_total", "Number of outbound bytes passed by a PF interface", []string{"interface", "family"}, nil)
	pfInterfaceOutBlockPackets = prometheus.NewDesc("opf_pf_interface_out_block_packets_total", "Number of outbound packets blocked by a PF interface", []string{"interface", "family"}, nil)
	pfInterfaceOutBlockBytes = prometheus.NewDesc("opf_pf_interface_out_block_bytes_total", "Number of outbout bytes blocked by a PF interface", []string{"interface", "family"}, nil)
)

type PfInterfaceCollector struct {}

func (pic PfInterfaceCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- pfInterfaceStates
	ch <- pfInterfaceRules
	ch <- pfInterfaceInPassPackets
	ch <- pfInterfaceInPassBytes
	ch <- pfInterfaceInBlockPackets
	ch <- pfInterfaceInBlockBytes
	ch <- pfInterfaceOutPassPackets
	ch <- pfInterfaceOutPassBytes
	ch <- pfInterfaceOutBlockPackets
	ch <- pfInterfaceOutBlockBytes
}

func (pic PfInterfaceCollector) Collect(ch chan<- prometheus.Metric) {
	const inet4 = "inet4"
	const inet6 = "inet6"

	ifaces, err := GetPfInterfaces()
	if err != nil {
		fmt.Println(err)
	}

	for _, iface := range ifaces {
		ch <- prometheus.MustNewConstMetric(pfInterfaceStates, prometheus.GaugeValue, float64(iface.References.States), iface.Interface)
		ch <- prometheus.MustNewConstMetric(pfInterfaceRules, prometheus.GaugeValue, float64(iface.References.Rules), iface.Interface)
		ch <- prometheus.MustNewConstMetric(pfInterfaceInPassPackets, prometheus.CounterValue, float64(iface.In4Pass.Packets), iface.Interface, inet4)
		ch <- prometheus.MustNewConstMetric(pfInterfaceInPassPackets, prometheus.CounterValue, float64(iface.In6Pass.Packets), iface.Interface, inet6)
		ch <- prometheus.MustNewConstMetric(pfInterfaceInPassBytes, prometheus.CounterValue, float64(iface.In4Pass.Bytes), iface.Interface, inet4)
		ch <- prometheus.MustNewConstMetric(pfInterfaceInPassBytes, prometheus.CounterValue, float64(iface.In6Pass.Bytes), iface.Interface, inet6)
		ch <- prometheus.MustNewConstMetric(pfInterfaceInBlockPackets, prometheus.CounterValue, float64(iface.In4Block.Packets), iface.Interface, inet4)
		ch <- prometheus.MustNewConstMetric(pfInterfaceInBlockPackets, prometheus.CounterValue, float64(iface.In6Block.Packets), iface.Interface, inet6)
		ch <- prometheus.MustNewConstMetric(pfInterfaceInBlockBytes, prometheus.CounterValue, float64(iface.In4Block.Bytes), iface.Interface, inet4)
		ch <- prometheus.MustNewConstMetric(pfInterfaceInBlockBytes, prometheus.CounterValue, float64(iface.In6Block.Bytes), iface.Interface, inet6)
		ch <- prometheus.MustNewConstMetric(pfInterfaceOutPassPackets, prometheus.CounterValue, float64(iface.Out4Pass.Packets), iface.Interface, inet4)
		ch <- prometheus.MustNewConstMetric(pfInterfaceOutPassPackets, prometheus.CounterValue, float64(iface.Out6Pass.Packets), iface.Interface, inet6)
		ch <- prometheus.MustNewConstMetric(pfInterfaceOutPassBytes, prometheus.CounterValue, float64(iface.Out4Pass.Bytes), iface.Interface, inet4)
		ch <- prometheus.MustNewConstMetric(pfInterfaceOutPassBytes, prometheus.CounterValue, float64(iface.Out6Pass.Bytes), iface.Interface, inet6)
		ch <- prometheus.MustNewConstMetric(pfInterfaceOutBlockPackets, prometheus.CounterValue, float64(iface.Out4Block.Packets), iface.Interface, inet4)
		ch <- prometheus.MustNewConstMetric(pfInterfaceOutBlockPackets, prometheus.CounterValue, float64(iface.Out6Block.Packets), iface.Interface, inet6)
		ch <- prometheus.MustNewConstMetric(pfInterfaceOutBlockBytes, prometheus.CounterValue, float64(iface.Out4Block.Bytes), iface.Interface, inet4)
		ch <- prometheus.MustNewConstMetric(pfInterfaceOutBlockBytes, prometheus.CounterValue, float64(iface.Out6Block.Bytes), iface.Interface, inet6)
	}

}

func pfInterfaceLine(fields []string) (int, int, error) {
	int1, err := strconv.Atoi(fields[2])
	if err != nil {
		return 0, 0, err
	}
	int2, err := strconv.Atoi(strings.TrimRight(fields[4], "]"))
	if err != nil {
		return 0, 0, err
	}
	return int1, int2, nil
}

func genPfInterface(lines []string) (*PfInterface, error) {
	ifLine := lines[0]
	iface := strings.TrimSpace(strings.Fields(ifLine)[0])

	lineValues := make(map[string][]string)

	for _, line := range lines {
		fields := strings.Fields(line)
		lineName := strings.Trim(fields[0], ":")
		lineValues[lineName] = fields[1:]
	}

	cleared := strings.Join(lineValues["Cleared"], " ")

	states, rules, err := pfInterfaceLine(lineValues["References"])
	if err != nil {
		return nil, fmt.Errorf("Could not parse references for pf interface %s: %w", iface, err)
	}

	i4pPkt, i4pByte, err := pfInterfaceLine(lineValues["In4/Pass"])
	if err != nil {
		return nil, fmt.Errorf("Could not parse in4/pass for pf interface %s: %w" , iface, err)
	}

	i4bPkt, i4bByte, err := pfInterfaceLine(lineValues["In4/Block"])
	if err != nil {
		return nil, fmt.Errorf("Could not parse in4/block for pf interface %s: %w", iface, err)
	}

	o4pPkt, o4pByte, err := pfInterfaceLine(lineValues["Out4/Pass"])
	if err != nil {
		return nil, fmt.Errorf("Could not parse out4/pass for pf interface %s: %w", iface, err)
	}

	o4bPkt, o4bByte, err := pfInterfaceLine(lineValues["Out4/Block"])
	if err != nil {
		return nil, fmt.Errorf("Could not parse out4/block for pf interface %s: %w", iface, err)
	}

	i6pPkt, i6pByte, err := pfInterfaceLine(lineValues["In6/Pass"])
	if err != nil {
		return nil, fmt.Errorf("Could not parse in6/pass for pf interface %s: %w", iface, err)
	}

	i6bPkt, i6bByte, err := pfInterfaceLine(lineValues["In6/Block"])
	if err != nil {
		return nil, fmt.Errorf("Could not parse in6/block for pf interface %s: %w", iface, err)
	}

	o6pPkt, o6pByte, err := pfInterfaceLine(lineValues["Out6/Pass"])
	if err != nil {
		return nil, fmt.Errorf("Could not parse out6/pass for pf interface %s: %w", iface, err)
	}

	o6bPkt, o6bByte, err := pfInterfaceLine(lineValues["Out6/Block"])
	if err != nil {
		return nil, fmt.Errorf("Could not parse out6/block for pf interface %s: %w", iface, err)
	}

	pfInterface := &PfInterface{}

	pfInterface.Interface = iface
	pfInterface.Cleared = cleared
	pfInterface.References.States = states
	pfInterface.References.Rules = rules
	pfInterface.In4Pass.Packets = i4pPkt
	pfInterface.In4Pass.Bytes = i4pByte
	pfInterface.In4Block.Packets = i4bPkt
	pfInterface.In4Block.Bytes = i4bByte
	pfInterface.Out4Pass.Packets = o4pPkt
	pfInterface.Out4Pass.Bytes = o4pByte
	pfInterface.Out4Block.Packets = o4bPkt
	pfInterface.Out4Block.Bytes = o4bByte
	pfInterface.In6Pass.Packets = i6pPkt
	pfInterface.In6Pass.Bytes = i6pByte
	pfInterface.In6Block.Packets = i6bPkt
	pfInterface.In6Block.Bytes = i6bByte
	pfInterface.Out6Pass.Packets = o6pPkt
	pfInterface.Out6Pass.Bytes = o6pByte
	pfInterface.Out6Block.Packets = o6bPkt
	pfInterface.Out6Block.Bytes = o6bByte

	return pfInterface, nil
}

func GetPfInterfaces() ([]*PfInterface, error) {
	outBytes, err := exec.Command("doas", "pfctl", "-vv", "-s", "Interface").Output()
	if err != nil {
		return nil, err
	}

	var interfaces []*PfInterface

	outString := string(outBytes)
	outLines := strings.Split(outString, "\n")

	groups := groupIndent(outLines)

	for _, group := range groups {
		iface, err := genPfInterface(group)
		if err != nil {
			fmt.Println(err)
			continue
		}
		interfaces = append(interfaces, iface)
	}

	return interfaces, nil
}
