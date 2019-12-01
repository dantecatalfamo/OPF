import React, { useState, useEffect } from 'react';
import { Descriptions, Badge, Typography } from 'antd';
import { getJSON } from '../helpers.js';
import { serverURL } from '../config.js';

const { Text } = Typography;
const { Item } = Descriptions;

const pfInfoURL = `${serverURL}/api/pf-info`;
const updateTime = 3000;

function PfInfo(props) {
  const [pfInfo, setPfInfo] = useState();

  useEffect(() => {
    getJSON(pfInfoURL).then(res => setPfInfo(res));
    const interval = setInterval(() => {
      getJSON(pfInfoURL).then(res => setPfInfo(res));
    }, updateTime);

    return () => {
      clearInterval(interval);
    };
  }, []);

  if (!pfInfo) {
    return "";
  }

  return (
    <div>
      <Descriptions column={{xl: 4, lg: 2, md: 2, sm: 1, xs: 1}} bordered>
        <Item label="Status" span={2}>
          <Badge status={pfInfo.status === "Enabled" ? "green" : "red" }/>
          {pfInfo.status}
        </Item>
        <Item label="Since" span={2}>{pfInfo.since}</Item>
        <Item label="Debug">{pfInfo.debug}</Item>
        <Item label="Host ID">{pfInfo.hostId}</Item>
        <Item label="Checksum" span={2}>{pfInfo.checksum}</Item>

        <Item label={<Text strong>State Table</Text>} span={4} />
        <Item label="Current Entries">{pfInfo.stateTable.currentEntries}</Item>
        <Item label="Half-Open TCP">{pfInfo.stateTable.halfOpenTcp}</Item>
        <Item label="Total Searches">{pfInfo.stateTable.searches.total}</Item>
        <Item label="Search Rate">{pfInfo.stateTable.searches.rate}/s</Item>
        <Item label="Total Inserts">{pfInfo.stateTable.inserts.total}</Item>
        <Item label="Insert Rate">{pfInfo.stateTable.inserts.rate}/s</Item>
        <Item label="Total Removals">{pfInfo.stateTable.removals.total}</Item>
        <Item label="Removal Rate">{pfInfo.stateTable.removals.rate}/s</Item>

        <Item label={<Text strong>Source Tracking Table</Text>}span={4} />
        <Item label="Current Entries" span={2}>{pfInfo.sourceTrackingTable.currentEntries}</Item>
        <Item label="Total Searches">{pfInfo.sourceTrackingTable.searches.total}</Item>
        <Item label="Search Rate">{pfInfo.sourceTrackingTable.searches.rate}/s</Item>
        <Item label="Total Inserts">{pfInfo.sourceTrackingTable.inserts.total}</Item>
        <Item label="Insert Rate">{pfInfo.sourceTrackingTable.inserts.rate}/s</Item>
        <Item label="Total Removals">{pfInfo.sourceTrackingTable.removals.total}</Item>
        <Item label="Removal Rate">{pfInfo.sourceTrackingTable.removals.rate}/s</Item>

        <Item label={<Text strong>Counters</Text>} span={4} />
        <Item label="Total Matches">{pfInfo.counters.match.total}</Item>
        <Item label="Match Rate">{pfInfo.counters.match.rate}/s</Item>
        <Item label="Total Bad Offsets">{pfInfo.counters.badOffsets.total}</Item>
        <Item label="Bad Offset Rate">{pfInfo.counters.badOffsets.rate}/s</Item>
        <Item label="Total Fragments">{pfInfo.counters.fragments.total}</Item>
        <Item label="Fragment Rate">{pfInfo.counters.fragments.rate}/s</Item>
        <Item label="Total Shorts">{pfInfo.counters.shorts.total}</Item>
        <Item label="Short Rate">{pfInfo.counters.shorts.rate}/s</Item>
        <Item label="Total Normalizes">{pfInfo.counters.normalize.total}</Item>
        <Item label="Normalize Rate">{pfInfo.counters.normalize.rate}/s</Item>
        <Item label="Total Memory">{pfInfo.counters.match.total}</Item>
        <Item label="Memory Rate">{pfInfo.counters.match.rate}/s</Item>
        <Item label="Total Bad Timestamps">{pfInfo.counters.badTimestamp.total}</Item>
        <Item label="Bad Timestamp Rate">{pfInfo.counters.badTimestamp.rate}/s</Item>
        <Item label="Total Congestion">{pfInfo.counters.congestion.total}</Item>
        <Item label="Congestion Rate">{pfInfo.counters.congestion.rate}/s</Item>
        <Item label="Total IP Options">{pfInfo.counters.ipOption.total}</Item>
        <Item label="IP Options Rate">{pfInfo.counters.ipOption.rate}/s</Item>
        <Item label="Total Protocol Checksums">{pfInfo.counters.protoCksum.total}</Item>
        <Item label="Protocol Checksum Rate">{pfInfo.counters.protoCksum.rate}/s</Item>
        <Item label="Total State Mismatches">{pfInfo.counters.stateMismatch.total}</Item>
        <Item label="State Mismatch Rate">{pfInfo.counters.stateMismatch.rate}/s</Item>
        <Item label="Total State Inserts">{pfInfo.counters.stateInsert.total}</Item>
        <Item label="State Insert Rate">{pfInfo.counters.stateInsert.rate}/s</Item>
        <Item label="Total State Limits">{pfInfo.counters.stateLimit.total}</Item>
        <Item label="State Limit Rate">{pfInfo.counters.stateLimit.rate}/s</Item>
        <Item label="Total Source Limits">{pfInfo.counters.srcLimit.total}</Item>
        <Item label="State Limit Rate">{pfInfo.counters.srcLimit.rate}/s</Item>
        <Item label="Total SynProxy">{pfInfo.counters.synproxy.total}</Item>
        <Item label="SynProxy Rate">{pfInfo.counters.synproxy.rate}/s</Item>
        <Item label="Total Translations">{pfInfo.counters.translate.total}</Item>
        <Item label="Translation Rate">{pfInfo.counters.translate.rate}/s</Item>
        <Item label="Total No Routes">{pfInfo.counters.noRoute.total}</Item>
        <Item label="No Route Rate" span={3}>{pfInfo.counters.noRoute.rate}/s</Item>

        <Item label={<Text strong>Limit Counters</Text>} span={4} />
        <Item label="Total Max States Per Rule">{pfInfo.limitCounters.maxStatesPerRule.total}</Item>
        <Item label="Max States Per Rule Rate">{pfInfo.limitCounters.maxStatesPerRule.rate}/s</Item>
        <Item label="Total Max Source States">{pfInfo.limitCounters.maxSrcStates.total}</Item>
        <Item label="Max Source States Rate">{pfInfo.limitCounters.maxSrcStates.rate}/s</Item>
        <Item label="Total Max Source Nodes">{pfInfo.limitCounters.maxSrcNodes.total}</Item>
        <Item label="Max Source Nodes Rate">{pfInfo.limitCounters.maxSrcNodes.rate}/s</Item>
        <Item label="Total Max Source Conn">{pfInfo.limitCounters.maxSrcConn.total}</Item>
        <Item label="Max Source Conn Rate">{pfInfo.limitCounters.maxSrcConn.rate}/s</Item>
        <Item label="Total Max Source Conn Rate">{pfInfo.limitCounters.maxSrcConnRate.total}</Item>
        <Item label="Max Source Conn Rate Rate">{pfInfo.limitCounters.maxSrcConnRate.rate}/s</Item>
        <Item label="Total Overload Table Insersions">{pfInfo.limitCounters.overloadTableInsertion.total}</Item>
        <Item label="Overload Table Insertion Rate">{pfInfo.limitCounters.overloadTableInsertion.rate}/s</Item>
        <Item label="Total SYN Floods Detected">{pfInfo.limitCounters.synFloodsDetected.total}</Item>
        <Item label="SYN Flood Detection Rate">{pfInfo.limitCounters.synFloodsDetected.rate}/s</Item>
        <Item label="Total SYN Cookies Sent">{pfInfo.limitCounters.syncookiesSent.total}</Item>
        <Item label="SYN Cookie Send Rate">{pfInfo.limitCounters.syncookiesSent.rate}/s</Item>
        <Item label="Total SYN Cookies Validated">{pfInfo.limitCounters.syncookiesValidated.total}</Item>
        <Item label="SYN Cookie Validation Rate" span={3}>{pfInfo.limitCounters.syncookiesValidated.rate}/s</Item>

        <Item label={<Text strong>Adaptive SYN Cookies Watermarks</Text>} span={4} />
        <Item label="Start">{pfInfo.adaptiveSyncookiesWatermarks.start}</Item>
        <Item label="End">{pfInfo.adaptiveSyncookiesWatermarks.end}</Item>
      </Descriptions>
    </div>
  );
}

export default PfInfo;
