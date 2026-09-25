package main

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

type PfRuleState struct {
	Rule           string `json:"rule"`
	Number         int    `json:"number"`
	Evaluations    int    `json:"evaluations"`
	Packets        int    `json:"packets"`
	Bytes          int    `json:"bytes"`
	States         int    `json:"states"`
	StateCreations int    `json:"stateCreations"`
	InsertionUID   int    `json:"insertionUid"`
	InsertionPID   int    `json:"insertionPid"`
}

func init() {
	prometheus.MustRegister(PfRuleStateCollector{})
}

var (
	pfRuleStateEvalDesc = prometheus.NewDesc("opf_pf_rule_evaluations_total", "Number of PF rule evaluations", []string{"number", "rule"}, nil)
	pfRuleStatePacketsDesc = prometheus.NewDesc("opf_pf_rule_packets_total", "Number of packets passed through a PF rule", []string{"number", "rule"}, nil)
	pfRuleStateBytesDesc = prometheus.NewDesc("opf_pf_rule_bytes_total", "Number of bytes passed through a PF rule", []string{"number", "rule"}, nil)
	pfRuleStateStatesDesc = prometheus.NewDesc("opf_pf_rule_states", "Number of active states for a PF rule", []string{"number", "rule"}, nil)
	pfRuleStateStateCreations = prometheus.NewDesc("opf_pf_rule_state_creations_total", "Number of states created by a PF rule", []string{"number", "rule"}, nil)
)

type PfRuleStateCollector struct{}

func (pfsc PfRuleStateCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- pfRuleStateEvalDesc
	ch <- pfRuleStatePacketsDesc
	ch <- pfRuleStateBytesDesc
	ch <- pfRuleStateStatesDesc
	ch <- pfRuleStateStateCreations
}

func (pfsc PfRuleStateCollector) Collect(ch chan<- prometheus.Metric) {
	rules, err := GetPfRuleStates()
	if err != nil {
		fmt.Println(err)
	}

	for _, rule := range rules {
		ch <- prometheus.MustNewConstMetric(pfRuleStateEvalDesc, prometheus.CounterValue, float64(rule.Evaluations), strconv.Itoa(rule.Number), rule.Rule)
		ch <- prometheus.MustNewConstMetric(pfRuleStatePacketsDesc, prometheus.CounterValue, float64(rule.Packets), strconv.Itoa(rule.Number), rule.Rule)
		ch <- prometheus.MustNewConstMetric(pfRuleStateBytesDesc, prometheus.CounterValue, float64(rule.Bytes), strconv.Itoa(rule.Number), rule.Rule)
		ch <- prometheus.MustNewConstMetric(pfRuleStateStatesDesc, prometheus.GaugeValue, float64(rule.States), strconv.Itoa(rule.Number), rule.Rule)
		ch <- prometheus.MustNewConstMetric(pfRuleStateStateCreations, prometheus.CounterValue, float64(rule.StateCreations), strconv.Itoa(rule.Number), rule.Rule)
	}
}

func genPfRuleState(lines []string) (*PfRuleState, error) {
	ruleFields := strings.SplitN(lines[0], " ", 2)
	number, err := strconv.Atoi(ruleFields[0][1:])
	if err != nil {
		return nil, fmt.Errorf("Failed to get pf rule number: %w", err)
	}

	rule := ruleFields[1]

	details := strings.Fields(lines[1])
	evaluations, err := strconv.Atoi(details[2])
	if err != nil {
		return nil, fmt.Errorf("Failed to get pf rule %d evaluations: %w", number, err)
	}

	packets, err := strconv.Atoi(details[4])
	if err != nil {
		return nil, fmt.Errorf("Failed to get pf %d rule evaluations: %w", number, err)
	}

	bytes, err := strconv.Atoi(details[6])
	if err != nil {
		return nil, fmt.Errorf("Failed to get pf rule %d bytes: %w", number, err)
	}

	trimmedSates := strings.TrimRight(details[8], "]")
	states, err := strconv.Atoi(trimmedSates)
	if err != nil {
		return nil, fmt.Errorf("Failed to get pf rule %d states: %w", number, err)
	}

	lastLine := strings.Fields(lines[2])

	insertionUid, err := strconv.Atoi(lastLine[3])
	if err != nil {
		return nil, fmt.Errorf("Failed to get pf rule %d insertion uid: %w", number, err)
	}

	insertionPid, err := strconv.Atoi(lastLine[5])
	if err != nil {
		return nil, fmt.Errorf("Failed to get pf rule %d insertion pid: %w", number, err)
	}

	trimmedStateCreations := strings.TrimRight(lastLine[8], "]")
	stateCreations, err := strconv.Atoi(trimmedStateCreations)
	if err != nil {
		return nil, fmt.Errorf("Failed to get pf rule %d state creations: %w", number, err)
	}

	pfRuleState := &PfRuleState{}

	pfRuleState.Number = number
	pfRuleState.Rule = rule
	pfRuleState.Evaluations = evaluations
	pfRuleState.Packets = packets
	pfRuleState.Bytes = bytes
	pfRuleState.States = states
	pfRuleState.StateCreations = stateCreations
	pfRuleState.InsertionUID = insertionUid
	pfRuleState.InsertionPID = insertionPid

	return pfRuleState, nil
}

func GetPfRuleStates() ([]*PfRuleState, error) {
	outBytes, err := exec.Command("doas", "pfctl", "-vv", "-s", "rules").Output()
	if err != nil {
		return nil, err
	}

	var rules []*PfRuleState

	outString := string(outBytes)
	outLines := strings.Split(outString, "\n")

	groups := groupIndent(outLines)

	for _, group := range groups {
		rule, err := genPfRuleState(group)
		if err != nil {
			fmt.Println(err)
			continue
		}
		rules = append(rules, rule)
	}

	return rules, nil
}
