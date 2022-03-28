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

func init() {
	prometheus.MustRegister(PfMemoryCollector{})
}

var (
	pfMemoryStatesDesc = prometheus.NewDesc("opf_pf_states_limit", "PF states limit", nil, nil)
	pfMemorySrcNodesDesc = prometheus.NewDesc("opf_pf_src_nodes_limit", "PF source nodes limit", nil, nil)
	pfMemoryFragsDesc = prometheus.NewDesc("opf_pf_frags_limit", "PF frags limit", nil, nil)
	pfMemoryTablesDesc = prometheus.NewDesc("opf_pf_tables_limit", "PF tables limit", nil, nil)
	pfMemoryTableEntriesDesc = prometheus.NewDesc("opf_pf_table_entries_limit", "PF table entries limit", nil, nil)
	pfMemoryPktDelayPktsDesc = prometheus.NewDesc("opf_pf_pkt_delay_pkts_limit", "PF pkt delay pkts limit", nil, nil)
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
	ch <- prometheus.MustNewConstMetric(pfMemorySrcNodesDesc, prometheus.GaugeValue, float64(pfMem.SrcNodes))
	ch <- prometheus.MustNewConstMetric(pfMemoryFragsDesc, prometheus.GaugeValue, float64(pfMem.Frags))
	ch <- prometheus.MustNewConstMetric(pfMemoryTablesDesc, prometheus.GaugeValue, float64(pfMem.Tables))
	ch <- prometheus.MustNewConstMetric(pfMemoryTableEntriesDesc, prometheus.GaugeValue, float64(pfMem.TableEntries))
	ch <- prometheus.MustNewConstMetric(pfMemoryPktDelayPktsDesc, prometheus.GaugeValue, float64(pfMem.PktDelayPkts))
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
	outBytes, err := exec.Command("doas", "pfctl", "-s", "memory").Output()
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
