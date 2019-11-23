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
			Rate  float64 `json:rate"`
		} `json:"maxSrcStates"`
		MaxSrcNodes struct {
			Total int     `json:"total"`
			Rate  float64 `json:rate"`
		} `json:"maxSrcNodes"`
		MaxSrcConn struct {
			Total int     `json:"total"`
			Rate  float64 `json:rate"`
		} `json:"maxSrcConn"`
		MaxSrcConnRate struct {
			Total int     `json:"total"`
			Rate  float64 `json:rate"`
		} `json:"maxSrcConnRate"`
		OverloadTableInsertion struct {
			Total int     `json:"total"`
			Rate  float64 `json:rate"`
		} `json:"overloadTableInsertion"`
		OverloadFlushStates struct {
			Total int     `json:"total"`
			Rate  float64 `json:rate"`
		} `json:"overloadFlushStates"`
		SynfloodsDetected struct {
			Total int     `json:"total"`
			Rate  float64 `json:rate"`
		} `json:"synFloodsDetected"`
		SyncookiesSent struct {
			Total int     `json:"total"`
			Rate  float64 `json:rate"`
		} `json:"syncookiesSent"`
		SyncookiesValidated struct {
			Total int     `json:"total"`
			Rate  float64 `json:rate"`
		} `json:"syncookiesValidated"`
	} `json:"limitCounters"`
	AdaptiveSyncookiesWatermarks struct {
		Start int `json:"start"`
		End   int `json:"end"`
	} `json:"adaptiveSyncookiesWatermarks"`
}

func pfInfoLine(row string) (int, float64, error) {
	rowFields := strings.Fields(row)
	total, err := strconv.Atoi(rowFields[len(rowFields)-2])
	if err != nil {
		return 0, 0, err
	}

	rateStr := strings.TrimRight(rowFields[len(rowFields)-1], "/s")
	rate, err := strconv.ParseFloat(rateStr, 64)
	if err != nil {
		return 0, 0, err
	}

	return total, rate, nil
}

func pfInfo() (*PfInfo, error) {
	outBytes, err := exec.Command("pfctl", "-v", "-s", "info").Output()
	if err != nil {
		return nil, err
	}

	info := &PfInfo{}

	outString := string(outBytes)
	outLines := strings.Split(outString, "\n")

	statusLine := outLines[0]
	statusFields := strings.Fields(statusLine)
	status := statusFields[1]
	since := strings.Join(statusFields[3:len(statusFields)-2], " ")

	info.Status = status
	info.Since = since
	info.Debug = statusFields[len(statusFields)-1]
	info.HostId = strings.Fields(outLines[2])[1]
	info.Checksum = strings.Fields(outLines[3])[1]

	groups := groupIndent(outLines)

	statesTable := groups[3]

	currentEntries := strings.Fields(statesTable[1])
	currentEntriesTotal, err := strconv.Atoi(currentEntries[2])
	if err != nil {
		return nil, err
	}
	info.StateTable.CurrentEntries = currentEntriesTotal

	halfOpenTcp := strings.Fields(statesTable[2])
	halfOpenTcpTotal, err := strconv.Atoi(halfOpenTcp[2])
	if err != nil {
		return nil, err
	}
	info.StateTable.HalfOpenTcp = halfOpenTcpTotal

	stateSearchesTotal, stateSearchesRate, err := pfInfoLine(statesTable[3])
	if err != nil {
		return nil, err
	}
	info.StateTable.Searches.Total = stateSearchesTotal
	info.StateTable.Searches.Rate = stateSearchesRate

	stateInsertTotal, stateInsertRate, err := pfInfoLine(statesTable[4])
	if err != nil {
		return nil, err
	}
	info.StateTable.Inserts.Total = stateInsertTotal
	info.StateTable.Inserts.Rate = stateInsertRate

	stateRemovalTotal, stateRemovalRate, err := pfInfoLine(statesTable[5])
	if err != nil {
		return nil, err
	}
	info.StateTable.Removals.Total = stateRemovalTotal
	info.StateTable.Removals.Rate = stateRemovalRate

	sourceTable := groups[4]

	sourceCurrent := strings.Fields(sourceTable[1])
	sourceCurrentTotal, err := strconv.Atoi(sourceCurrent[2])
	if err != nil {
		return nil, err
	}
	info.SourceTrackingTable.CurrentEntries = sourceCurrentTotal

	sourceSearchTotal, sourceSearchRate, err := pfInfoLine(sourceTable[2])
	if err != nil {
		return nil, err
	}
	info.SourceTrackingTable.Searches.Total = sourceSearchTotal
	info.SourceTrackingTable.Searches.Rate = sourceSearchRate

	sourceInsertTotal, sourceInsertRate, err := pfInfoLine(sourceTable[3])
	if err != nil {
		return nil, err
	}
	info.SourceTrackingTable.Inserts.Total = sourceInsertTotal
	info.SourceTrackingTable.Inserts.Rate = sourceInsertRate

	sourceRemovalTotal, sourceRemovalRate, err := pfInfoLine(sourceTable[4])
	if err != nil {
		return nil, err
	}
	info.SourceTrackingTable.Removals.Total = sourceRemovalTotal
	info.SourceTrackingTable.Removals.Rate = sourceRemovalRate

	counterTable := groups[5]

	counterMatchTotal, counterMatchRate, err := pfInfoLine(counterTable[1])
	if err != nil {
		return nil, err
	}
	info.Counters.Match.Total = counterMatchTotal
	info.Counters.Match.Rate = counterMatchRate

	counterBadOffsetsTotal, counterBadOffsetsRate, err := pfInfoLine(counterTable[2])
	if err != nil {
		return nil, err
	}
	info.Counters.BadOffsets.Total = counterBadOffsetsTotal
	info.Counters.BadOffsets.Rate = counterBadOffsetsRate

	counterFragmentsTotal, counterFragmentsRate, err := pfInfoLine(counterTable[3])
	if err != nil {
		return nil, err
	}
	info.Counters.Fragments.Total = counterFragmentsTotal
	info.Counters.Fragments.Rate = counterFragmentsRate

	counterShortTotal, counterShortRate, err := pfInfoLine(counterTable[4])
	if err != nil {
		return nil, err
	}
	info.Counters.Short.Total = counterShortTotal
	info.Counters.Short.Rate = counterShortRate

	counterNormalizeTotal, counterNormalizeRate, err := pfInfoLine(counterTable[5])
	if err != nil {
		return nil, err
	}
	info.Counters.Normalize.Total = counterNormalizeTotal
	info.Counters.Normalize.Rate = counterNormalizeRate

	counterMemoryTotal, counterMemoryRate, err := pfInfoLine(counterTable[6])
	if err != nil {
		return nil, err
	}
	info.Counters.Memory.Total = counterMemoryTotal
	info.Counters.Memory.Rate = counterMemoryRate

	counterBadTimestampTotal, counterBadTimestampRate, err := pfInfoLine(counterTable[7])
	if err != nil {
		return nil, err
	}
	info.Counters.BadTimestamp.Total = counterBadTimestampTotal
	info.Counters.BadTimestamp.Rate = counterBadTimestampRate

	counterCongestionTotal, counterCongestionRate, err := pfInfoLine(counterTable[8])
	if err != nil {
		return nil, err
	}
	info.Counters.Congestion.Total = counterCongestionTotal
	info.Counters.Congestion.Rate = counterCongestionRate

	counterIpOptionTotal, counterIpOptionRate, err := pfInfoLine(counterTable[9])
	if err != nil {
		return nil, err
	}
	info.Counters.IpOption.Total = counterIpOptionTotal
	info.Counters.IpOption.Rate = counterIpOptionRate

	counterProtoCksumTotal, counterProtoCksumRate, err := pfInfoLine(counterTable[10])
	if err != nil {
		return nil, err
	}
	info.Counters.ProtoCksum.Total = counterProtoCksumTotal
	info.Counters.ProtoCksum.Rate = counterProtoCksumRate

	counterStateMismatchTotal, counterStateMismatchRate, err := pfInfoLine(counterTable[11])
	if err != nil {
		return nil, err
	}
	info.Counters.StateMismatch.Total = counterStateMismatchTotal
	info.Counters.StateMismatch.Rate = counterStateMismatchRate

	counterStateInsertTotal, counterStateInsertRate, err := pfInfoLine(counterTable[12])
	if err != nil {
		return nil, err
	}
	info.Counters.StateInsert.Total = counterStateInsertTotal
	info.Counters.StateInsert.Rate = counterStateInsertRate

	counterStateLimitTotal, counterStateLimitRate, err := pfInfoLine(counterTable[13])
	if err != nil {
		return nil, err
	}
	info.Counters.StateLimit.Total = counterStateLimitTotal
	info.Counters.StateLimit.Rate = counterStateLimitRate

	counterSrcLimitTotal, counterSrcLimitRate, err := pfInfoLine(counterTable[14])
	if err != nil {
		return nil, err
	}
	info.Counters.SrcLimit.Total = counterSrcLimitTotal
	info.Counters.SrcLimit.Rate = counterSrcLimitRate

	counterSynproxyTotal, counterSynproxyRate, err := pfInfoLine(counterTable[15])
	if err != nil {
		return nil, err
	}
	info.Counters.Synproxy.Total = counterSynproxyTotal
	info.Counters.Synproxy.Rate = counterSynproxyRate

	counterTranslateTotal, counterTranslateRate, err := pfInfoLine(counterTable[16])
	if err != nil {
		return nil, err
	}
	info.Counters.Translate.Total = counterTranslateTotal
	info.Counters.Translate.Rate = counterTranslateRate

	counterNoRouteTotal, counterNoRouteRate, err := pfInfoLine(counterTable[17])
	if err != nil {
		return nil, err
	}
	info.Counters.NoRoute.Total = counterNoRouteTotal
	info.Counters.NoRoute.Rate = counterNoRouteRate

	limitTable := groups[6]

	limitMaxStatesPerRuleTotal, limitMaxStatesPerRuleRate, err := pfInfoLine(limitTable[1])
	if err != nil {
		return nil, err
	}
	info.LimitCounters.MaxStatesPerRule.Total = limitMaxStatesPerRuleTotal
	info.LimitCounters.MaxStatesPerRule.Rate = limitMaxStatesPerRuleRate

	limitMaxSrcStatesTotal, limitMaxSrcStatesRate, err := pfInfoLine(limitTable[2])
	if err != nil {
		return nil, err
	}
	info.LimitCounters.MaxSrcStates.Total = limitMaxSrcStatesTotal
	info.LimitCounters.MaxSrcStates.Rate = limitMaxSrcStatesRate

	limitMaxSrcNodesTotal, limitMaxSrcNodesRate, err := pfInfoLine(limitTable[3])
	if err != nil {
		return nil, err
	}
	info.LimitCounters.MaxSrcNodes.Total = limitMaxSrcNodesTotal
	info.LimitCounters.MaxSrcNodes.Rate = limitMaxSrcNodesRate

	limitMaxSrcConnTotal, limitMaxSrcConnRate, err := pfInfoLine(limitTable[4])
	if err != nil {
		return nil, err
	}
	info.LimitCounters.MaxSrcConn.Total = limitMaxSrcConnTotal
	info.LimitCounters.MaxSrcConn.Rate = limitMaxSrcConnRate

	limitMaxSrcConnRateTotal, limitMaxSrcConnRateRate, err := pfInfoLine(limitTable[5])
	if err != nil {
		return nil, err
	}
	info.LimitCounters.MaxSrcConnRate.Total = limitMaxSrcConnRateTotal
	info.LimitCounters.MaxSrcConnRate.Rate = limitMaxSrcConnRateRate

	limitOverloadTableInsertionTotal, limitOverloadTableInsertionRate, err := pfInfoLine(limitTable[6])
	if err != nil {
		return nil, err
	}
	info.LimitCounters.OverloadTableInsertion.Total = limitOverloadTableInsertionTotal
	info.LimitCounters.OverloadTableInsertion.Rate = limitOverloadTableInsertionRate

	limitOverloadFlushStatesTotal, limitOverloadFlushStatesRate, err := pfInfoLine(limitTable[7])
	if err != nil {
		return nil, err
	}
	info.LimitCounters.OverloadFlushStates.Total = limitOverloadFlushStatesTotal
	info.LimitCounters.OverloadFlushStates.Rate = limitOverloadFlushStatesRate

	limitSynfloodsDetectedTotal, limitSynfloodsDetectedRate, err := pfInfoLine(limitTable[8])
	if err != nil {
		return nil, err
	}
	info.LimitCounters.SynfloodsDetected.Total = limitSynfloodsDetectedTotal
	info.LimitCounters.SynfloodsDetected.Rate = limitSynfloodsDetectedRate

	limitSyncookiesSentTotal, limitSyncookiesSentRate, err := pfInfoLine(limitTable[9])
	if err != nil {
		return nil, err
	}
	info.LimitCounters.SyncookiesSent.Total = limitSyncookiesSentTotal
	info.LimitCounters.SyncookiesSent.Rate = limitSyncookiesSentRate

	limitSyncookiesValidatedTotal, limitSyncookiesValidatedRate, err := pfInfoLine(limitTable[10])
	if err != nil {
		return nil, err
	}
	info.LimitCounters.SyncookiesValidated.Total = limitSyncookiesValidatedTotal
	info.LimitCounters.SyncookiesValidated.Rate = limitSyncookiesValidatedRate

	adaptiveTable := groups[7]

	startFields := strings.Fields(adaptiveTable[1])
	start, err := strconv.Atoi(startFields[1])
	if err != nil {
		return nil, err
	}
	info.AdaptiveSyncookiesWatermarks.Start = start

	endFields := strings.Fields(adaptiveTable[2])
	end, err := strconv.Atoi(endFields[1])
	if err != nil {
		return nil, err
	}
	info.AdaptiveSyncookiesWatermarks.End = end

	return info, nil
}
