package main

import (
	"os/exec"
	"strconv"
	"strings"
)

type PfInfo struct {
	Status     string `json:"status"`
	Since      string `json:"since"`
	Debug      string `json:"debug"`
	HostId     string `json:"hostId"`
	Checksum   string `json:"checksum"`
	StateTable struct {
		CurrentEntries int `json:"currentEntries"`
		HalfOpenTcp    int `json:"halfOpenTcp"`
		Searches       struct {
			Total int     `json:"total"`
			Rate  float64 `json:"rate"`
		} `json:"searches"`
		Inserts struct {
			Total int     `json:"total"`
			Rate  float64 `json:"rate"`
		} `json:"inserts"`
		Removals struct {
			Total int     `json:"total"`
			Rate  float64 `json:"rate"`
		} `json:"removals"`
	} `json:"stateTable"`
	SourceTrackingTable struct {
		CurrentEntries int `json:"currentEntries"`
		Searches       struct {
			Total int     `json:"total"`
			Rate  float64 `json:"rate"`
		} `json:"searches"`
		Inserts struct {
			Total int     `json:"total"`
			Rate  float64 `json:"rate"`
		} `json:"inserts"`
		Removals struct {
			Total int     `json:"total"`
			Rate  float64 `json:"rate"`
		} `json:"removals"`
	} `json:"sourceTrackingTable"`
	Counters struct {
		Match struct {
			Total int     `json:"total"`
			Rate  float64 `json:"rate"`
		} `json:"match"`
		BadOffsets struct {
			Total int     `json:"total"`
			Rate  float64 `json:"rate"`
		} `json:"badOffsets"`
		Fragments struct {
			Total int     `json:"total"`
			Rate  float64 `json:"rate"`
		} `json:"fragments"`
		Short struct {
			Total int     `json:"total"`
			Rate  float64 `json:"rate"`
		} `json:"shorts"`
		Normalize struct {
			Total int     `json:"total"`
			Rate  float64 `json:"rate"`
		} `json:"normalize"`
		Memory struct {
			Total int     `json:"total"`
			Rate  float64 `json:"rate"`
		} `json:"memory"`
		BadTimestamp struct {
			Total int     `json:"total"`
			Rate  float64 `json:"rate"`
		} `json:"badTimestamp"`
		Congestion struct {
			Total int     `json:"total"`
			Rate  float64 `json:"rate"`
		} `json:"congestion"`
		IpOption struct {
			Total int     `json:"total"`
			Rate  float64 `json:"rate"`
		} `json:"ipOption"`
		ProtoCksum struct {
			Total int     `json:"total"`
			Rate  float64 `json:"rate"`
		} `json:"protoCksum"`
		StateMismatch struct {
			Total int     `json:"total"`
			Rate  float64 `json:"rate"`
		} `json:"stateMismatch"`
		StateInsert struct {
			Total int     `json:"total"`
			Rate  float64 `json:"rate"`
		} `json:"stateInsert"`
		StateLimit struct {
			Total int     `json:"total"`
			Rate  float64 `json:"rate"`
		} `json:"stateLimit"`
		SrcLimit struct {
			Total int     `json:"total"`
			Rate  float64 `json:"rate"`
		} `json:"srcLimit"`
		Synproxy struct {
			Total int     `json:"total"`
			Rate  float64 `json:"rate"`
		} `json:"synproxy"`
		Translate struct {
			Total int     `json:"total"`
			Rate  float64 `json:"rate"`
		} `json:"translate"`
		NoRoute struct {
			Total int     `json:"total"`
			Rate  float64 `json:"rate"`
		} `json:"noRoute"`
	} `json:"counters"`
	LimitCounters struct {
		MaxStatesPerRule struct {
			Total int     `json:"total"`
			Rate  float64 `json:"rate"`
		} `json:"maxStatesPerRule"`
		MaxSrcStates struct {
			Total int     `json:"total"`
			Rate  float64 `json:"rate"`
		} `json:"maxSrcStates"`
		MaxSrcNodes struct {
			Total int     `json:"total"`
			Rate  float64 `json:"rate"`
		} `json:"maxSrcNodes"`
		MaxSrcConn struct {
			Total int     `json:"total"`
			Rate  float64 `json:"rate"`
		} `json:"maxSrcConn"`
		MaxSrcConnRate struct {
			Total int     `json:"total"`
			Rate  float64 `json:"rate"`
		} `json:"maxSrcConnRate"`
		OverloadTableInsertion struct {
			Total int     `json:"total"`
			Rate  float64 `json:"rate"`
		} `json:"overloadTableInsertion"`
		OverloadFlushStates struct {
			Total int     `json:"total"`
			Rate  float64 `json:"rate"`
		} `json:"overloadFlushStates"`
		SynfloodsDetected struct {
			Total int     `json:"total"`
			Rate  float64 `json:"rate"`
		} `json:"synFloodsDetected"`
		SyncookiesSent struct {
			Total int     `json:"total"`
			Rate  float64 `json:"rate"`
		} `json:"syncookiesSent"`
		SyncookiesValidated struct {
			Total int     `json:"total"`
			Rate  float64 `json:"rate"`
		} `json:"syncookiesValidated"`
	} `json:"limitCounters"`
	AdaptiveSyncookiesWatermarks struct {
		Start int `json:"start"`
		End   int `json:"end"`
	} `json:"adaptiveSyncookiesWatermarks"`
}

func pfInfoLine(line string) (int, float64, error) {
	lineFields := strings.Fields(line)
	total, err := strconv.Atoi(lineFields[len(lineFields)-2])
	if err != nil {
		return 0, 0, err
	}

	rateStr := strings.TrimRight(lineFields[len(lineFields)-1], "/s")
	rate, err := strconv.ParseFloat(rateStr, 64)
	if err != nil {
		return 0, 0, err
	}

	return total, rate, nil
}

func GetPfInfo() (*PfInfo, error) {
	outBytes, err := exec.Command("doas", "pfctl", "-v", "-s", "info").Output()
	if err != nil {
		return nil, err
	}

	outString := string(outBytes)
	outLines := strings.Split(outString, "\n")

	statusLine := outLines[0]
	statusFields := strings.Fields(statusLine)
	status := statusFields[1]
	since := strings.Join(statusFields[3:len(statusFields)-2], " ")
	debug := statusFields[len(statusFields)-1]
	hostId := strings.Fields(outLines[2])[1]
	checksum := strings.Fields(outLines[3])[1]

	groups := groupIndent(outLines)
	numberGroups := len(groups)
	extraGroups := numberGroups - 8

	statesTable := groups[extraGroups+3]
	currentEntries := strings.Fields(statesTable[1])
	stateCurrentEntriesTotal, err := strconv.Atoi(currentEntries[2])
	if err != nil {
		return nil, err
	}

	halfOpenTcp := strings.Fields(statesTable[2])
	stateHalfOpenTcpTotal, err := strconv.Atoi(halfOpenTcp[2])
	if err != nil {
		return nil, err
	}

	stateSearchesTotal, stateSearchesRate, err := pfInfoLine(statesTable[3])
	if err != nil {
		return nil, err
	}

	stateInsertTotal, stateInsertRate, err := pfInfoLine(statesTable[4])
	if err != nil {
		return nil, err
	}

	stateRemovalTotal, stateRemovalRate, err := pfInfoLine(statesTable[5])
	if err != nil {
		return nil, err
	}

	sourceTable := groups[extraGroups+4]
	sourceCurrent := strings.Fields(sourceTable[1])
	sourceCurrentTotal, err := strconv.Atoi(sourceCurrent[2])
	if err != nil {
		return nil, err
	}

	sourceSearchTotal, sourceSearchRate, err := pfInfoLine(sourceTable[2])
	if err != nil {
		return nil, err
	}

	sourceInsertTotal, sourceInsertRate, err := pfInfoLine(sourceTable[3])
	if err != nil {
		return nil, err
	}

	sourceRemovalTotal, sourceRemovalRate, err := pfInfoLine(sourceTable[4])
	if err != nil {
		return nil, err
	}

	counterTable := groups[extraGroups+5]
	counterMatchTotal, counterMatchRate, err := pfInfoLine(counterTable[1])
	if err != nil {
		return nil, err
	}

	counterBadOffsetsTotal, counterBadOffsetsRate, err := pfInfoLine(counterTable[2])
	if err != nil {
		return nil, err
	}

	counterFragmentsTotal, counterFragmentsRate, err := pfInfoLine(counterTable[3])
	if err != nil {
		return nil, err
	}

	counterShortTotal, counterShortRate, err := pfInfoLine(counterTable[4])
	if err != nil {
		return nil, err
	}

	counterNormalizeTotal, counterNormalizeRate, err := pfInfoLine(counterTable[5])
	if err != nil {
		return nil, err
	}

	counterMemoryTotal, counterMemoryRate, err := pfInfoLine(counterTable[6])
	if err != nil {
		return nil, err
	}

	counterBadTimestampTotal, counterBadTimestampRate, err := pfInfoLine(counterTable[7])
	if err != nil {
		return nil, err
	}

	counterCongestionTotal, counterCongestionRate, err := pfInfoLine(counterTable[8])
	if err != nil {
		return nil, err
	}

	counterIpOptionTotal, counterIpOptionRate, err := pfInfoLine(counterTable[9])
	if err != nil {
		return nil, err
	}

	counterProtoCksumTotal, counterProtoCksumRate, err := pfInfoLine(counterTable[10])
	if err != nil {
		return nil, err
	}

	counterStateMismatchTotal, counterStateMismatchRate, err := pfInfoLine(counterTable[11])
	if err != nil {
		return nil, err
	}

	counterStateInsertTotal, counterStateInsertRate, err := pfInfoLine(counterTable[12])
	if err != nil {
		return nil, err
	}

	counterStateLimitTotal, counterStateLimitRate, err := pfInfoLine(counterTable[13])
	if err != nil {
		return nil, err
	}

	counterSrcLimitTotal, counterSrcLimitRate, err := pfInfoLine(counterTable[14])
	if err != nil {
		return nil, err
	}

	counterSynproxyTotal, counterSynproxyRate, err := pfInfoLine(counterTable[15])
	if err != nil {
		return nil, err
	}

	counterTranslateTotal, counterTranslateRate, err := pfInfoLine(counterTable[16])
	if err != nil {
		return nil, err
	}

	counterNoRouteTotal, counterNoRouteRate, err := pfInfoLine(counterTable[17])
	if err != nil {
		return nil, err
	}

	limitTable := groups[extraGroups+6]
	limitMaxStatesPerRuleTotal, limitMaxStatesPerRuleRate, err := pfInfoLine(limitTable[1])
	if err != nil {
		return nil, err
	}

	limitMaxSrcStatesTotal, limitMaxSrcStatesRate, err := pfInfoLine(limitTable[2])
	if err != nil {
		return nil, err
	}

	limitMaxSrcNodesTotal, limitMaxSrcNodesRate, err := pfInfoLine(limitTable[3])
	if err != nil {
		return nil, err
	}

	limitMaxSrcConnTotal, limitMaxSrcConnRate, err := pfInfoLine(limitTable[4])
	if err != nil {
		return nil, err
	}

	limitMaxSrcConnRateTotal, limitMaxSrcConnRateRate, err := pfInfoLine(limitTable[5])
	if err != nil {
		return nil, err
	}

	limitOverloadTableInsertionTotal, limitOverloadTableInsertionRate, err := pfInfoLine(limitTable[6])
	if err != nil {
		return nil, err
	}

	limitOverloadFlushStatesTotal, limitOverloadFlushStatesRate, err := pfInfoLine(limitTable[7])
	if err != nil {
		return nil, err
	}

	limitSynfloodsDetectedTotal, limitSynfloodsDetectedRate, err := pfInfoLine(limitTable[8])
	if err != nil {
		return nil, err
	}

	limitSyncookiesSentTotal, limitSyncookiesSentRate, err := pfInfoLine(limitTable[9])
	if err != nil {
		return nil, err
	}

	limitSyncookiesValidatedTotal, limitSyncookiesValidatedRate, err := pfInfoLine(limitTable[10])
	if err != nil {
		return nil, err
	}

	adaptiveTable := groups[extraGroups+7]
	startFields := strings.Fields(adaptiveTable[1])
	start, err := strconv.Atoi(startFields[1])
	if err != nil {
		return nil, err
	}

	endFields := strings.Fields(adaptiveTable[2])
	end, err := strconv.Atoi(endFields[1])
	if err != nil {
		return nil, err
	}

	pfInfo := &PfInfo{}

	pfInfo.Status = status
	pfInfo.Since = since
	pfInfo.Debug = debug
	pfInfo.HostId = hostId
	pfInfo.Checksum = checksum
	pfInfo.StateTable.CurrentEntries = stateCurrentEntriesTotal
	pfInfo.StateTable.HalfOpenTcp = stateHalfOpenTcpTotal
	pfInfo.StateTable.Searches.Total = stateSearchesTotal
	pfInfo.StateTable.Searches.Rate = stateSearchesRate
	pfInfo.StateTable.Inserts.Total = stateInsertTotal
	pfInfo.StateTable.Inserts.Rate = stateInsertRate
	pfInfo.StateTable.Removals.Total = stateRemovalTotal
	pfInfo.StateTable.Removals.Rate = stateRemovalRate
	pfInfo.SourceTrackingTable.CurrentEntries = sourceCurrentTotal
	pfInfo.SourceTrackingTable.Searches.Total = sourceSearchTotal
	pfInfo.SourceTrackingTable.Searches.Rate = sourceSearchRate
	pfInfo.SourceTrackingTable.Inserts.Total = sourceInsertTotal
	pfInfo.SourceTrackingTable.Inserts.Rate = sourceInsertRate
	pfInfo.SourceTrackingTable.Removals.Total = sourceRemovalTotal
	pfInfo.SourceTrackingTable.Removals.Rate = sourceRemovalRate
	pfInfo.Counters.Match.Total = counterMatchTotal
	pfInfo.Counters.Match.Rate = counterMatchRate
	pfInfo.Counters.BadOffsets.Total = counterBadOffsetsTotal
	pfInfo.Counters.BadOffsets.Rate = counterBadOffsetsRate
	pfInfo.Counters.Fragments.Total = counterFragmentsTotal
	pfInfo.Counters.Fragments.Rate = counterFragmentsRate
	pfInfo.Counters.Short.Total = counterShortTotal
	pfInfo.Counters.Short.Rate = counterShortRate
	pfInfo.Counters.Normalize.Total = counterNormalizeTotal
	pfInfo.Counters.Normalize.Rate = counterNormalizeRate
	pfInfo.Counters.Memory.Total = counterMemoryTotal
	pfInfo.Counters.Memory.Rate = counterMemoryRate
	pfInfo.Counters.BadTimestamp.Total = counterBadTimestampTotal
	pfInfo.Counters.BadTimestamp.Rate = counterBadTimestampRate
	pfInfo.Counters.Congestion.Total = counterCongestionTotal
	pfInfo.Counters.Congestion.Rate = counterCongestionRate
	pfInfo.Counters.IpOption.Total = counterIpOptionTotal
	pfInfo.Counters.IpOption.Rate = counterIpOptionRate
	pfInfo.Counters.ProtoCksum.Total = counterProtoCksumTotal
	pfInfo.Counters.ProtoCksum.Rate = counterProtoCksumRate
	pfInfo.Counters.StateMismatch.Total = counterStateMismatchTotal
	pfInfo.Counters.StateMismatch.Rate = counterStateMismatchRate
	pfInfo.Counters.StateInsert.Total = counterStateInsertTotal
	pfInfo.Counters.StateInsert.Rate = counterStateInsertRate
	pfInfo.Counters.StateLimit.Total = counterStateLimitTotal
	pfInfo.Counters.StateLimit.Rate = counterStateLimitRate
	pfInfo.Counters.SrcLimit.Total = counterSrcLimitTotal
	pfInfo.Counters.SrcLimit.Rate = counterSrcLimitRate
	pfInfo.Counters.Synproxy.Total = counterSynproxyTotal
	pfInfo.Counters.Synproxy.Rate = counterSynproxyRate
	pfInfo.Counters.Translate.Total = counterTranslateTotal
	pfInfo.Counters.Translate.Rate = counterTranslateRate
	pfInfo.Counters.NoRoute.Total = counterNoRouteTotal
	pfInfo.Counters.NoRoute.Rate = counterNoRouteRate
	pfInfo.LimitCounters.MaxStatesPerRule.Total = limitMaxStatesPerRuleTotal
	pfInfo.LimitCounters.MaxStatesPerRule.Rate = limitMaxStatesPerRuleRate
	pfInfo.LimitCounters.MaxSrcStates.Total = limitMaxSrcStatesTotal
	pfInfo.LimitCounters.MaxSrcStates.Rate = limitMaxSrcStatesRate
	pfInfo.LimitCounters.MaxSrcNodes.Total = limitMaxSrcNodesTotal
	pfInfo.LimitCounters.MaxSrcNodes.Rate = limitMaxSrcNodesRate
	pfInfo.LimitCounters.MaxSrcConn.Total = limitMaxSrcConnTotal
	pfInfo.LimitCounters.MaxSrcConn.Rate = limitMaxSrcConnRate
	pfInfo.LimitCounters.MaxSrcConnRate.Total = limitMaxSrcConnRateTotal
	pfInfo.LimitCounters.MaxSrcConnRate.Rate = limitMaxSrcConnRateRate
	pfInfo.LimitCounters.OverloadTableInsertion.Total = limitOverloadTableInsertionTotal
	pfInfo.LimitCounters.OverloadTableInsertion.Rate = limitOverloadTableInsertionRate
	pfInfo.LimitCounters.OverloadFlushStates.Total = limitOverloadFlushStatesTotal
	pfInfo.LimitCounters.OverloadFlushStates.Rate = limitOverloadFlushStatesRate
	pfInfo.LimitCounters.SynfloodsDetected.Total = limitSynfloodsDetectedTotal
	pfInfo.LimitCounters.SynfloodsDetected.Rate = limitSynfloodsDetectedRate
	pfInfo.LimitCounters.SyncookiesSent.Total = limitSyncookiesSentTotal
	pfInfo.LimitCounters.SyncookiesSent.Rate = limitSyncookiesSentRate
	pfInfo.LimitCounters.SyncookiesValidated.Total = limitSyncookiesValidatedTotal
	pfInfo.LimitCounters.SyncookiesValidated.Rate = limitSyncookiesValidatedRate
	pfInfo.AdaptiveSyncookiesWatermarks.Start = start
	pfInfo.AdaptiveSyncookiesWatermarks.End = end

	return pfInfo, nil
}
