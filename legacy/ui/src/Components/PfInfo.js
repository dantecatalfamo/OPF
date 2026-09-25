import React, { useState } from 'react';
import {
  Descriptions, Badge, Col, Row, Card, Statistic, Spin,
} from 'antd';
import { useJsonUpdates } from '../helpers.ts';
import { serverURL } from '../config.ts';

const { Item } = Descriptions;

const pfInfoURL = `${serverURL}/api/pf-info`;
const updateTime = 3000;

function PfInfo() {
  const [pfInfo, setPfInfo] = useState();

  useJsonUpdates(pfInfoURL, setPfInfo, updateTime);

  if (!pfInfo) {
    return (
      <Spin>
        <Card style={{ margin: '30px' }} />
      </Spin>
    );
  }

  return (
    <Col xxl={{ span: 16, offset: 4 }} xl={{ span: 20, offset: 2 }} lg={{ span: 24 }}>
      <Card style={{ marginBottom: '12px', marginTop: '12px' }}>
        <Descriptions
          column={{
            xxl: 2, xl: 2, lg: 2, md: 1, sm: 1, xs: 1,
          }}
          bordered
        >
          <Item label="Status" span={2}>
            <Badge status={pfInfo.status === 'Enabled' ? 'green' : 'red'} />
            {pfInfo.status}
          </Item>
          <Item label="Since" span={2}>{pfInfo.since}</Item>
          <Item label="Debug">{pfInfo.debug}</Item>
          <Item label="Host ID">{pfInfo.hostId}</Item>
          <Item label="Checksum" span={2}>{pfInfo.checksum}</Item>
        </Descriptions>
      </Card>

      <Card title="State Table" style={{ marginBottom: '12px' }}>
        <Row>
          <Col span={6}><Statistic title="Current Entries" value={pfInfo.stateTable.currentEntries} /></Col>
          <Col span={6}><Statistic title="Half-Open TCP" value={pfInfo.stateTable.halfOpenTcp} /></Col>
          <Col span={6}><Statistic title="Total Searches" value={pfInfo.stateTable.searches.total} /></Col>
          <Col span={6}><Statistic title="Search Rate" value={pfInfo.stateTable.searches.rate} suffix="/s" /></Col>
          <Col span={6}><Statistic title="Total Inserts" value={pfInfo.stateTable.inserts.total} /></Col>
          <Col span={6}><Statistic title="Insert Rate" value={pfInfo.stateTable.inserts.rate} suffix="/s" /></Col>
          <Col span={6}><Statistic title="Total Removals" value={pfInfo.stateTable.removals.total} /></Col>
          <Col span={6}><Statistic title="Removal Rate" value={pfInfo.stateTable.removals.rate} suffix="/s" /></Col>
        </Row>
      </Card>

      <Card title="Source Tracking Table" style={{ marginBottom: '12px' }}>
        <Col span={12}><Statistic title="Current Entries" value={pfInfo.sourceTrackingTable.currentEntries} /></Col>
        <Col span={6}><Statistic title="Total Searches" value={pfInfo.sourceTrackingTable.searches.total} /></Col>
        <Col span={6}><Statistic title="Search Rate" value={pfInfo.sourceTrackingTable.searches.rate} suffix="/s" /></Col>
        <Col span={6}><Statistic title="Total Inserts" value={pfInfo.sourceTrackingTable.inserts.total} /></Col>
        <Col span={6}><Statistic title="Insert Rate" value={pfInfo.sourceTrackingTable.inserts.rate} suffix="/s" /></Col>
        <Col span={6}><Statistic title="Total Removals" value={pfInfo.sourceTrackingTable.removals.total} /></Col>
        <Col span={6}><Statistic title="Removal Rate" value={pfInfo.sourceTrackingTable.removals.rate} suffix="/s" /></Col>
      </Card>

      <Card title="Counters" style={{ marginBottom: '12px' }}>
        <Col span={6}><Statistic title="Total Matches" value={pfInfo.counters.match.total} /></Col>
        <Col span={6}><Statistic title="Match Rate" value={pfInfo.counters.match.rate} suffix="/s" /></Col>
        <Col span={6}><Statistic title="Total Bad Offsets" value={pfInfo.counters.badOffsets.total} /></Col>
        <Col span={6}><Statistic title="Bad Offset Rate" value={pfInfo.counters.badOffsets.rate} suffix="/s" /></Col>
        <Col span={6}><Statistic title="Total Fragments" value={pfInfo.counters.fragments.total} /></Col>
        <Col span={6}><Statistic title="Fragment Rate" value={pfInfo.counters.fragments.rate} suffix="/s" /></Col>
        <Col span={6}><Statistic title="Total Shorts" value={pfInfo.counters.shorts.total} /></Col>
        <Col span={6}><Statistic title="Short Rate" value={pfInfo.counters.shorts.rate} suffix="/s" /></Col>
        <Col span={6}><Statistic title="Total Normalizes" value={pfInfo.counters.normalize.total} /></Col>
        <Col span={6}><Statistic title="Normalize Rate" value={pfInfo.counters.normalize.rate} suffix="/s" /></Col>
        <Col span={6}><Statistic title="Total Memory" value={pfInfo.counters.match.total} /></Col>
        <Col span={6}><Statistic title="Memory Rate" value={pfInfo.counters.match.rate} suffix="/s" /></Col>
        <Col span={6}><Statistic title="Total Bad Timestamps" value={pfInfo.counters.badTimestamp.total} /></Col>
        <Col span={6}><Statistic title="Bad Timestamp Rate" value={pfInfo.counters.badTimestamp.rate} suffix="/s" /></Col>
        <Col span={6}><Statistic title="Total Congestion" value={pfInfo.counters.congestion.total} /></Col>
        <Col span={6}><Statistic title="Congestion Rate" value={pfInfo.counters.congestion.rate} suffix="/s" /></Col>
        <Col span={6}><Statistic title="Total IP Options" value={pfInfo.counters.ipOption.total} /></Col>
        <Col span={6}><Statistic title="IP Options Rate" value={pfInfo.counters.ipOption.rate} suffix="/s" /></Col>
        <Col span={6}><Statistic title="Total Protocol Checksums" value={pfInfo.counters.protoCksum.total} /></Col>
        <Col span={6}><Statistic title="Protocol Checksum Rate" value={pfInfo.counters.protoCksum.rate} suffix="/s" /></Col>
        <Col span={6}><Statistic title="Total State Mismatches" value={pfInfo.counters.stateMismatch.total} /></Col>
        <Col span={6}><Statistic title="State Mismatch Rate" value={pfInfo.counters.stateMismatch.rate} suffix="/s" /></Col>
        <Col span={6}><Statistic title="Total State Inserts" value={pfInfo.counters.stateInsert.total} /></Col>
        <Col span={6}><Statistic title="State Insert Rate" value={pfInfo.counters.stateInsert.rate} suffix="/s" /></Col>
        <Col span={6}><Statistic title="Total State Limits" value={pfInfo.counters.stateLimit.total} /></Col>
        <Col span={6}><Statistic title="State Limit Rate" value={pfInfo.counters.stateLimit.rate} suffix="/s" /></Col>
        <Col span={6}><Statistic title="Total Source Limits" value={pfInfo.counters.srcLimit.total} /></Col>
        <Col span={6}><Statistic title="State Limit Rate" value={pfInfo.counters.srcLimit.rate} suffix="/s" /></Col>
        <Col span={6}><Statistic title="Total SynProxy" value={pfInfo.counters.synproxy.total} /></Col>
        <Col span={6}><Statistic title="SynProxy Rate" value={pfInfo.counters.synproxy.rate} suffix="/s" /></Col>
        <Col span={6}><Statistic title="Total Translations" value={pfInfo.counters.translate.total} /></Col>
        <Col span={6}><Statistic title="Translation Rate" value={pfInfo.counters.translate.rate} suffix="/s" /></Col>
        <Col span={6}><Statistic title="Total No Routes" value={pfInfo.counters.noRoute.total} /></Col>
        <Col span={6}><Statistic title="No Route Rate" span={3} value={pfInfo.counters.noRoute.rate} suffix="/s" /></Col>
      </Card>
      <Card title="Limit Counters" style={{ marginBottom: '12px' }}>
        <Col span={6}><Statistic title="Total Max States Per Rule" value={pfInfo.limitCounters.maxStatesPerRule.total} /></Col>
        <Col span={6}><Statistic title="Max States Per Rule Rate" value={pfInfo.limitCounters.maxStatesPerRule.rate} suffix="/s" /></Col>
        <Col span={6}><Statistic title="Total Max Source States" value={pfInfo.limitCounters.maxSrcStates.total} /></Col>
        <Col span={6}><Statistic title="Max Source States Rate" value={pfInfo.limitCounters.maxSrcStates.rate} suffix="/s" /></Col>
        <Col span={6}><Statistic title="Total Max Source Nodes" value={pfInfo.limitCounters.maxSrcNodes.total} /></Col>
        <Col span={6}><Statistic title="Max Source Nodes Rate" value={pfInfo.limitCounters.maxSrcNodes.rate} suffix="/s" /></Col>
        <Col span={6}><Statistic title="Total Max Source Conn" value={pfInfo.limitCounters.maxSrcConn.total} /></Col>
        <Col span={6}><Statistic title="Max Source Conn Rate" value={pfInfo.limitCounters.maxSrcConn.rate} suffix="/s" /></Col>
        <Col span={6}><Statistic title="Total Max Source Conn Rate" value={pfInfo.limitCounters.maxSrcConnRate.total} /></Col>
        <Col span={6}><Statistic title="Max Source Conn Rate Rate" value={pfInfo.limitCounters.maxSrcConnRate.rate} suffix="/s" /></Col>
        <Col span={6}><Statistic title="Total Overload Table Insersions" value={pfInfo.limitCounters.overloadTableInsertion.total} /></Col>
        <Col span={6}><Statistic title="Overload Table Insertion Rate" value={pfInfo.limitCounters.overloadTableInsertion.rate} suffix="/s" /></Col>
        <Col span={6}><Statistic title="Total SYN Floods Detected" value={pfInfo.limitCounters.synFloodsDetected.total} /></Col>
        <Col span={6}><Statistic title="SYN Flood Detection Rate" value={pfInfo.limitCounters.synFloodsDetected.rate} suffix="/s" /></Col>
        <Col span={6}><Statistic title="Total SYN Cookies Sent" value={pfInfo.limitCounters.syncookiesSent.total} /></Col>
        <Col span={6}><Statistic title="SYN Cookie Send Rate" value={pfInfo.limitCounters.syncookiesSent.rate} suffix="/s" /></Col>
        <Col span={6}><Statistic title="Total SYN Cookies Validated" value={pfInfo.limitCounters.syncookiesValidated.total} /></Col>
        <Col span={6}><Statistic title="SYN Cookie Validation Rate" span={3} value={pfInfo.limitCounters.syncookiesValidated.rate} suffix="/s" /></Col>
      </Card>
      <Card title="Adaptive SYN Cookies Watermarks" style={{ marginBottom: '12px' }}>
        <Row>
          <Col span={6}><Statistic title="Start" value={pfInfo.adaptiveSyncookiesWatermarks.start} /></Col>
          <Col span={6}><Statistic title="End" value={pfInfo.adaptiveSyncookiesWatermarks.end} /></Col>
        </Row>
      </Card>
    </Col>
  );
}

export default PfInfo;
