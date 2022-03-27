package main

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

type PfMemory struct {
	States       int `json:"states"`
	SrcNodes     int `json:"srcNodes"`
	Frags        int `json:"frags"`
	Tables       int `json:"tables"`
	TableEntries int `json:"tableEntries"`
	PktDelayPkts int `json:"pktDelayPkts"`
}

var (
	pfMemoryStatesDesc = prometheus.NewDesc("opf_pf_memory_states", "PF memory states", nil, nil)
	pfMemorySrcNodesDesc = prometheus.NewDesc("opf_pf_memory_src_nodes", "PF memory source nodes", nil, nil)
	pfMemoryFragsDesc = prometheus.NewDesc("opf_pf_memory_frags", "PF memory frags", nil, nil)
	pfMemoryTablesDesc = prometheus.NewDesc("opf_pf_memory_tables", "PF memory tables", nil, nil)
	pfMemoryTableEntriesDesc = prometheus.NewDesc("opf_pf_table_entries", "PF memory table entries", nil, nil)
	pfMemoryPktDelayPktsDesc = prometheus.NewDesc("opf_pf_pkt_delay_pkts", "PF memory pkt delay pkts", nil, nil)
)

type PfMemoryCollector struct{}

func (pfmc PfMemoryCollector) Describe(ch chan<- *prometheus.Desc) {
	prometheus.DescribeByCollect(pfmc, ch)
}

func (pfmc PfMemoryCollector) Collect(ch chan<- prometheus.Metric) {
	pfMem, err := GetPfMemory()
	if err != nil {
		fmt.Println(err)
	}
	ch <- prometheus.MustNewConstMetric(pfMemoryStatesDesc, prometheus.GaugeValue, float64(pfMem.States))
}

func NewPfMemoryCollector() prometheus.Collector {
	return PfMemoryCollector{}
}

func genPfMemoryLine(line string) (int, error) {
	fields := strings.Fields(line)
	num := fields[3]
	return strconv.Atoi(num)
}

func GetPfMemory() (*PfMemory, error) {
	outBytes, err := exec.Command("pfctl", "-s", "memory").Output()
	if err != nil {
		return nil, err
	}

	out := string(outBytes)
	lines := strings.Split(out, "\n")

	states, err := genPfMemoryLine(lines[0])
	if err != nil {
		return nil, err
	}

	srcNodes, err := genPfMemoryLine(lines[1])
	if err != nil {
		return nil, err
	}

	frags, err := genPfMemoryLine(lines[2])
	if err != nil {
		return nil, err
	}

	tables, err := genPfMemoryLine(lines[3])
	if err != nil {
		return nil, err
	}

	tableEntries, err := genPfMemoryLine(lines[4])
	if err != nil {
		return nil, err
	}

	pktDelayPkts, err := genPfMemoryLine(lines[5])
	if err != nil {
		return nil, err
	}

	pfm := &PfMemory{}
	pfm.States = states
	pfm.SrcNodes = srcNodes
	pfm.Frags = frags
	pfm.Tables = tables
	pfm.TableEntries = tableEntries
	pfm.PktDelayPkts = pktDelayPkts

	return pfm, nil
}
