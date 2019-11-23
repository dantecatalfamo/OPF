package main

import (
	"fmt"
	"os/exec"
	"strings"
	"strconv"
)

type PfRuleState struct {
	Rule           string `json:"rule"`
	Number         int    `json:"number"`
	Evaluations    int    `json:"evaluations"`
	Packets        int    `json:"packets"`
	Bytes          int    `json:"bytes"`
	States         int    `json:"bytes"`
	StateCreations int    `json:"stateCreations"`
}

func genPfRuleState(lines []string) (*PfRuleState, error) {
	ruleFields := strings.SplitN(lines[0], " ", 2)
	number, err := strconv.Atoi(ruleFields[0][1:])
	if err != nil {
		return nil, err
	}

	rule := ruleFields[1]

	details := strings.Fields(lines[1])
	evaluations, err := strconv.Atoi(details[2])
	if err != nil {
		return nil, err
	}

	packets, err := strconv.Atoi(details[4])
	if err != nil {
		return nil, err
	}

	bytes, err := strconv.Atoi(details[6])
	if err != nil {
		return nil, err
	}

	trimmedSates := strings.TrimRight(details[8], "]")
	states, err := strconv.Atoi(trimmedSates)
	if err != nil {
		return nil, err
	}

	lastLine := strings.Fields(lines[2])
	trimmedStateCreations := strings.TrimRight(lastLine[8], "]")
	stateCreations, err := strconv.Atoi(trimmedStateCreations)
	if err != nil {
		return nil, err
	}

	pfRuleState := &PfRuleState{}

	pfRuleState.Number = number
	pfRuleState.Rule = rule
	pfRuleState.Evaluations = evaluations
	pfRuleState.Packets = packets
	pfRuleState.Bytes = bytes
	pfRuleState.States = states
	pfRuleState.StateCreations = stateCreations

	return pfRuleState, nil
}

func pfRuleStates() ([]*PfRuleState, error) {
	outBytes, err := exec.Command("pfctl", "-vv", "-s", "rules").Output()
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
