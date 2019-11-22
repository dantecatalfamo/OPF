package main

import (
	// "fmt"
	"os/exec"
	"strings"
	"strconv"
)

type PfInfo struct {
	Status     string
	Since      string
	Debug      string
	HostId     string
	Checksum   string
	StateTable struct {
		CurrentEntries int
		HalfOpenTcp    int
		Searches       struct {
			Total int
			Rate  float64
		}
		Inserts struct {
			Total int
			Rate  float64
		}
		Removals struct {
			Total int
			Rate  float64
		}
	}
	SourceTrackingTable struct {
		CurrentEntries int
		Searches       struct {
			Total int
			Rate  float64
		}
		Inserts struct {
			Total int
			Rate  float64
		}
		Removals struct {
			Total int
			Rate  float64
		}
	}
	Counters struct {
		Match struct {
			Total int
			Rate  float64
		}
		BadOffsets struct {
			Total int
			Rate  float64
		}
		Fragments struct {
			Total int
			Rate  float64
		}
		Short struct {
			Total int
			Rate  float64
		}
		Normalize struct {
			Total int
			Rate  float64
		}
		Memory struct {
			Total int
			Rate  float64
		}
		BadTimestamp struct {
			Total int
			Rate  float64
		}
		Congestion struct {
			Total int
			Rate  float64
		}
		IpOption struct {
			Total int
			Rate  float64
		}
		ProtoCksum struct {
			Total int
			Rate  float64
		}
		StateMismatch struct {
			Total int
			Rate  float64
		}
		StateInsert struct {
			Total int
			Rate  float64
		}
		StateLimit struct {
			Total int
			Rate  float64
		}
		SrcLimit struct {
			Total int
			Rate  float64
		}
		Synproxy struct {
			Total int
			Rate  float64
		}
		Translate struct {
			Total int
			Rate  float64
		}
		NoRoute struct {
			Total int
			Rate  float64
		}
	}
	LimitCounters struct {
		MaxStatesPerRule struct {
			Total int
			Rate  float64
		}
		MaxSrcStates struct {
			Total int
			Rate  float64
		}
		MaxSrcNodes struct {
			Total int
			Rate  float64
		}
		MaxSrcConn struct {
			Total int
			Rate  float64
		}
		MaxSrcConnRate struct {
			Total int
			Rate  float64
		}
		OverloadTableInsertion struct {
			Total int
			Rate  float64
		}
		OverloadFlushStates struct {
			Total int
			Rate  float64
		}
		SynfloodsDetected struct {
			Total int
			Rate  float64
		}
		SyncookiesSent struct {
			Total int
			Rate  float64
		}
		SyncookiesValidated struct {
			Total int
			Rate  float64
		}
	}
	AdaptiveSyncookiesWatermarks struct {
		Start int
		End   int
	}
}

func infoRow(row string) (int, float64, error) {
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

	stateSearchesTotal, stateSearchesRate, err := infoRow(statesTable[3])
	if err != nil {
		return nil, err
	}
	info.StateTable.Searches.Total = stateSearchesTotal
	info.StateTable.Searches.Rate = stateSearchesRate

	stateInsertTotal, stateInsertRate, err := infoRow(statesTable[4])
	if err != nil {
		return nil, err
	}
	info.StateTable.Inserts.Total = stateInsertTotal
	info.StateTable.Inserts.Rate = stateInsertRate

	stateRemovalTotal, stateRemovalRate, err := infoRow(statesTable[5])
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

	sourceSearchTotal, sourceSearchRate, err := infoRow(sourceTable[2])
	if err != nil {
		return nil, err
	}
	info.SourceTrackingTable.Searches.Total = sourceSearchTotal
	info.SourceTrackingTable.Searches.Rate = sourceSearchRate

	sourceInsertTotal, sourceInsertRate, err := infoRow(sourceTable[3])
	if err != nil {
		return nil, err
	}
	info.SourceTrackingTable.Inserts.Total = sourceInsertTotal
	info.SourceTrackingTable.Inserts.Rate = sourceInsertRate

	sourceRemovalTotal, sourceRemovalRate, err := infoRow(sourceTable[4])
	if err != nil {
		return nil, err
	}
	info.SourceTrackingTable.Removals.Total = sourceRemovalTotal
	info.SourceTrackingTable.Removals.Rate = sourceRemovalRate

	counterTable := groups[5]

	counterMatchTotal, counterMatchRate, err := infoRow(counterTable[1])
	if err != nil {
		return nil, err
	}
	info.Counters.Match.Total = counterMatchTotal
	info.Counters.Match.Rate = counterMatchRate

	counterBadOffsetsTotal, counterBadOffsetsRate, err := infoRow(counterTable[2])
	if err != nil {
		return nil, err
	}
	info.Counters.BadOffsets.Total = counterBadOffsetsTotal
	info.Counters.BadOffsets.Rate = counterBadOffsetsRate

	counterFragmentsTotal, counterFragmentsRate, err := infoRow(counterTable[3])
	if err != nil {
		return nil, err
	}
	info.Counters.Fragments.Total = counterFragmentsTotal
	info.Counters.Fragments.Rate = counterFragmentsRate

	counterShortTotal, counterShortRate, err := infoRow(counterTable[4])
	if err != nil {
		return nil, err
	}
	info.Counters.Short.Total = counterShortTotal
	info.Counters.Short.Rate = counterShortRate

	counterNormalizeTotal, counterNormalizeRate, err := infoRow(counterTable[5])
	if err != nil {
		return nil, err
	}
	info.Counters.Normalize.Total = counterNormalizeTotal
	info.Counters.Normalize.Rate = counterNormalizeRate

	counterMemoryTotal, counterMemoryRate, err := infoRow(counterTable[6])
	if err != nil {
		return nil, err
	}
	info.Counters.Memory.Total = counterMemoryTotal
	info.Counters.Memory.Rate = counterMemoryRate

	counterBadTimestampTotal, counterBadTimestampRate, err := infoRow(counterTable[7])
	if err != nil {
		return nil, err
	}
	info.Counters.BadTimestamp.Total = counterBadTimestampTotal
	info.Counters.BadTimestamp.Rate = counterBadTimestampRate

	counterCongestionTotal, counterCongestionRate, err := infoRow(counterTable[8])
	if err != nil {
		return nil, err
	}
	info.Counters.Congestion.Total = counterCongestionTotal
	info.Counters.Congestion.Rate = counterCongestionRate

	counterIpOptionTotal, counterIpOptionRate, err := infoRow(counterTable[9])
	if err != nil {
		return nil, err
	}
	info.Counters.IpOption.Total = counterIpOptionTotal
	info.Counters.IpOption.Rate = counterIpOptionRate

	counterProtoCksumTotal, counterProtoCksumRate, err := infoRow(counterTable[10])
	if err != nil {
		return nil, err
	}
	info.Counters.ProtoCksum.Total = counterProtoCksumTotal
	info.Counters.ProtoCksum.Rate = counterProtoCksumRate

	counterStateMismatchTotal, counterStateMismatchRate, err := infoRow(counterTable[11])
	if err != nil {
		return nil, err
	}
	info.Counters.StateMismatch.Total = counterStateMismatchTotal
	info.Counters.StateMismatch.Rate = counterStateMismatchRate

	counterStateInsertTotal, counterStateInsertRate, err := infoRow(counterTable[12])
	if err != nil {
		return nil, err
	}
	info.Counters.StateInsert.Total = counterStateInsertTotal
	info.Counters.StateInsert.Rate = counterStateInsertRate

	counterStateLimitTotal, counterStateLimitRate, err := infoRow(counterTable[13])
	if err != nil {
		return nil, err
	}
	info.Counters.StateLimit.Total = counterStateLimitTotal
	info.Counters.StateLimit.Rate = counterStateLimitRate

	counterSrcLimitTotal, counterSrcLimitRate, err := infoRow(counterTable[14])
	if err != nil {
		return nil, err
	}
	info.Counters.SrcLimit.Total = counterSrcLimitTotal
	info.Counters.SrcLimit.Rate = counterSrcLimitRate

	counterSynproxyTotal, counterSynproxyRate, err := infoRow(counterTable[15])
	if err != nil {
		return nil, err
	}
	info.Counters.Synproxy.Total = counterSynproxyTotal
	info.Counters.Synproxy.Rate = counterSynproxyRate

	counterTranslateTotal, counterTranslateRate, err := infoRow(counterTable[16])
	if err != nil {
		return nil, err
	}
	info.Counters.Translate.Total = counterTranslateTotal
	info.Counters.Translate.Rate = counterTranslateRate

	counterNoRouteTotal, counterNoRouteRate, err := infoRow(counterTable[17])
	if err != nil {
		return nil, err
	}
	info.Counters.NoRoute.Total = counterNoRouteTotal
	info.Counters.NoRoute.Rate = counterNoRouteRate

	limitTable := groups[6]

	limitMaxStatesPerRuleTotal, limitMaxStatesPerRuleRate, err := infoRow(limitTable[1])
	if err != nil {
		return nil, err
	}
	info.LimitCounters.MaxStatesPerRule.Total = limitMaxStatesPerRuleTotal
	info.LimitCounters.MaxStatesPerRule.Rate = limitMaxStatesPerRuleRate

	limitMaxSrcStatesTotal, limitMaxSrcStatesRate, err := infoRow(limitTable[2])
	if err != nil {
		return nil, err
	}
	info.LimitCounters.MaxSrcStates.Total = limitMaxSrcStatesTotal
	info.LimitCounters.MaxSrcStates.Rate = limitMaxSrcStatesRate

	limitMaxSrcNodesTotal, limitMaxSrcNodesRate, err := infoRow(limitTable[3])
	if err != nil {
		return nil, err
	}
	info.LimitCounters.MaxSrcNodes.Total = limitMaxSrcNodesTotal
	info.LimitCounters.MaxSrcNodes.Rate = limitMaxSrcNodesRate

	limitMaxSrcConnTotal, limitMaxSrcConnRate, err := infoRow(limitTable[4])
	if err != nil {
		return nil, err
	}
	info.LimitCounters.MaxSrcConn.Total = limitMaxSrcConnTotal
	info.LimitCounters.MaxSrcConn.Rate = limitMaxSrcConnRate

	limitMaxSrcConnRateTotal, limitMaxSrcConnRateRate, err := infoRow(limitTable[5])
	if err != nil {
		return nil, err
	}
	info.LimitCounters.MaxSrcConnRate.Total = limitMaxSrcConnRateTotal
	info.LimitCounters.MaxSrcConnRate.Rate = limitMaxSrcConnRateRate

	limitOverloadTableInsertionTotal, limitOverloadTableInsertionRate, err := infoRow(limitTable[6])
	if err != nil {
		return nil, err
	}
	info.LimitCounters.OverloadTableInsertion.Total = limitOverloadTableInsertionTotal
	info.LimitCounters.OverloadTableInsertion.Rate = limitOverloadTableInsertionRate

	limitOverloadFlushStatesTotal, limitOverloadFlushStatesRate, err := infoRow(limitTable[7])
	if err != nil {
		return nil, err
	}
	info.LimitCounters.OverloadFlushStates.Total = limitOverloadFlushStatesTotal
	info.LimitCounters.OverloadFlushStates.Rate = limitOverloadFlushStatesRate

	limitSynfloodsDetectedTotal, limitSynfloodsDetectedRate, err := infoRow(limitTable[8])
	if err != nil {
		return nil, err
	}
	info.LimitCounters.SynfloodsDetected.Total = limitSynfloodsDetectedTotal
	info.LimitCounters.SynfloodsDetected.Rate = limitSynfloodsDetectedRate

	limitSyncookiesSentTotal, limitSyncookiesSentRate, err := infoRow(limitTable[9])
	if err != nil {
		return nil, err
	}
	info.LimitCounters.SyncookiesSent.Total = limitSyncookiesSentTotal
	info.LimitCounters.SyncookiesSent.Rate = limitSyncookiesSentRate

	limitSyncookiesValidatedTotal, limitSyncookiesValidatedRate, err := infoRow(limitTable[10])
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
