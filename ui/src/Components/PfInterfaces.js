import React, { useState, useEffect, useReducer } from 'react';
import { Card, Statistic, Col, Row, Descriptions, Typography, Divider, Spin, Collapse } from 'antd';
import { ResponsiveContainer, ComposedChart, Bar, Area, CartesianGrid, XAxis, YAxis, Tooltip, Legend } from 'recharts';
import { getJSON, useJsonUpdates } from '../helpers.js';
import { serverURL } from '../config.js';
import './PfInterfaces.css';
import { formatTimeStr } from 'antd/lib/statistic/utils';

const { Panel } = Collapse;

const pfInterfacesURL = `${serverURL}/api/pf-interfaces`;
const updateTime = 2000;
const historyLength = 90;
const mbits = true;

function PfInterface(props) {
  const iface = props.iface;

  const ipv4 = [
    iface.in4pass.bytes, iface.in4block.bytes,
    iface.out4pass.bytes, iface.out4block.bytes,
  ].some(el => el > 0);

  const ipv6 = [
    iface.in6pass.bytes, iface.in6block.bytes,
    iface.out6pass.bytes, iface.out6block.bytes,
  ].some(el => el > 0);

  const ipv4Stats = ipv4 ? (
    <Row>
      <Col xl={6} span={12}><Statistic title="In Pass IPv4 (Packets)" value={iface.in4pass.packets}/></Col>
      <Col xl={6} span={12}><Statistic title="In Pass IPv4 (Bytes)" value={iface.in4pass.bytes}/></Col>
      <Col xl={6} span={12}><Statistic title="In Block IPv4 (Packets)" value={iface.in4block.packets}/></Col>
      <Col xl={6} span={12}><Statistic title="In Block IPv4 (Bytes)" value={iface.in4block.bytes}/></Col>
      <Col xl={6} span={12}><Statistic title="Out Pass IPv4 (Packets)" value={iface.out4pass.packets}/></Col>
      <Col xl={6} span={12}><Statistic title="Out Pass IPv4 (Bytes)" value={iface.out4pass.bytes}/></Col>
      <Col xl={6} span={12}><Statistic title="Out Block IPv4 (Packets)" value={iface.out4block.packets}/></Col>
      <Col xl={6} span={12}><Statistic title="Out Block IPv4 (Bytes)" value={iface.out4block.bytes}/></Col>
    </Row>
  ) : (
    <Typography>No IPv4 traffic</Typography>
  );

  const ipv6Stats = ipv6 ? (
    <Row>
      <Col xl={6} span={12}><Statistic title="In Pass IPv6 (Packets)" value={iface.in6pass.packets}/></Col>
      <Col xl={6} span={12}><Statistic title="In Pass IPv6 (Bytes)" value={iface.in6pass.bytes}/></Col>
      <Col xl={6} span={12}><Statistic title="In Block IPv6 (Packets)" value={iface.in6block.packets}/></Col>
      <Col xl={6} span={12}><Statistic title="In Block IPv6 (Bytes)" value={iface.in6block.bytes}/></Col>
      <Col xl={6} span={12}><Statistic title="Out Pass IPv6 (Packets)" value={iface.out6pass.packets}/></Col>
      <Col xl={6} span={12}><Statistic title="Out Pass IPv6 (Bytes)" value={iface.out6pass.bytes}/></Col>
      <Col xl={6} span={12}><Statistic title="Out Block IPv6 (Packets)" value={iface.out6block.packets}/></Col>
      <Col xl={6} span={12}><Statistic title="Out Block IPv6 (Bytes)" value={iface.out6block.bytes}/></Col>
    </Row>
  ) : (
    <Typography>No IPv6 traffic</Typography>
  );

  const graph = (
    <ResponsiveContainer height={250}>
      <ComposedChart data={iface.history} onClick={console.log}>
        <Area
          dataKey="pass4in"
          name="IPv4 Pass In"
          isAnimationActive={false}
          stroke="green"
          fill="green"
          stackId="passIn"
        />
        <Area
          dataKey="pass6in"
          name="IPv6 Pass In"
          isAnimationActive={false}
          stroke="lightgreen"
          fill="lightgreen"
          stackId="passIn"
        />
        <Area
          dataKey="pass4out"
          name="IPv4 Pass Out"
          isAnimationActive={false}
          stroke="red"
          fill="red"
          stackId="passOut"
        />
        <Area
          dataKey="pass6out"
          name="IPv6 Pass Out"
          isAnimationActive={false}
          stroke="pink"
          fill="pink"
          stackId="passOut"
        />
        <Bar
          dataKey="block4in"
          barSize={10}
          isAnimationActive={false}
          name="IPv4 Block In"
          fill="#667C26"
          stackId="blockIn"
        />
        <Bar
          dataKey="block6in"
          barSize={10}
          isAnimationActive={false}
          name="IPv6 Block In"
          fill="#848B79"
          stackId="blockIn"
        />
        <Bar
          dataKey="block4out"
          barSize={10}
          isAnimationActive={false}
          name="IPv4 Block Out"
          fill="#9F000F"
          stackId="blockOut"
        />
        <Bar
          dataKey="block6out"
          barSize={10}
          isAnimationActive={false}
          name="IPv6 Block Out"
          fill="#C24641"
          stackId="blockOut"
        />
        <Tooltip
          isAnimationActive={false}
          formatter={(value, name, props) => {
            const abs = Math.abs(value);
            if (abs < 0.001) {
              return `${(abs*1024*1024).toFixed(2)} B/s`;
            } else if (abs < 1) {
              return `${(abs*1024).toFixed(2)} KB/s`;
            } else if (abs < 1024) {
              return `${abs.toFixed(2)} MB/s`;
            } else {
              return `${(abs/1024).toFixed(2)} GB/s`;
            }
          }}
        />
        <Legend />
        <CartesianGrid strokeDasharray="3 3" />
        <XAxis
          dataKey="time"
          minTickGap={50}
        />
        <YAxis />
      </ComposedChart>
    </ResponsiveContainer>
  );

  return (
    <Col
      key={iface.interface}
      xxl={{span: 18, offset: 3}}
      xl={{span: 20, offset: 2}}
      lg={{span: 24}}
    >
      <Card title={iface.interface} style={{marginTop: "12px"}}>
        {(ipv4 || ipv6) ? graph : ""}
        <Collapse>
          <Panel header="Statistics">
            <Row>
              <Col xl={6} span={12}><Statistic title="References (States)" value={iface.references.states}/></Col>
              <Col xl={6} span={12}><Statistic title="References (Rules)" value={iface.references.rules}/></Col>
              <Col xl={12} span={24}><Typography>Counters last cleared {iface.cleared}</Typography></Col>
            </Row>
            <Divider />
            {ipv4Stats}
            <Divider />
            {ipv6Stats}
          </Panel>
        </Collapse>
      </Card>
    </Col>
  );
}

function PfInterfaces(props) {
  const [interfaces, updateInterfaces] = useReducer((state, update) => {
    let ifaces = {};
    update.forEach(iface => {
      const newDate = new Date();
      const name = iface.interface;
      ifaces[name] = iface;
      ifaces[name].date = newDate;
      const newPass4In = iface.in4pass.bytes;
      const newPass4Out = iface.out4pass.bytes;
      const newPass6In = iface.in6pass.bytes;
      const newPass6Out = iface.out6pass.bytes;
      const newBlock4In = iface.in4block.bytes;
      const newBlock4Out = iface.out4block.bytes;
      const newBlock6In = iface.in6block.bytes;
      const newBlock6Out = iface.out6block.bytes;
      let oldDate;
      let oldPass4In;
      let oldPass4Out;
      let oldPass6In;
      let oldPass6Out;
      let oldBlock4In;
      let oldBlock4Out;
      let oldBlock6In;
      let oldBlock6Out;
      let oldHistory;
      if (!state || state === {} || !state[name]) {
        oldDate = 0;
        oldPass4In = newPass4In;
        oldPass4Out = newPass4Out;
        oldPass6In = newPass6In;
        oldPass6Out = newPass6Out;
        oldBlock4In = newBlock4In;
        oldBlock4Out = newBlock4Out;
        oldBlock6In = newBlock6In;
        oldBlock6Out = newBlock6Out;
        oldHistory = [];
      } else {
        oldDate = state[name].date;
        oldPass4In = state[name].in4pass.bytes;
        oldPass4Out = state[name].out4pass.bytes;
        oldPass6In = state[name].in6pass.bytes;
        oldPass6Out = state[name].out6pass.bytes;
        oldBlock4In = state[name].in4block.bytes;
        oldBlock4Out = state[name].out4block.bytes;
        oldBlock6In = state[name].in6block.bytes;
        oldBlock6Out = state[name].out6block.bytes;
        oldHistory = state[name].history;
      }
      const date = new Date();
      const hours = (date.getHours() < 10 ? '0' : '') + date.getHours();
      const minutes = (date.getMinutes() < 10 ? '0' : '') + date.getMinutes();
      const seconds = (date.getSeconds() < 10 ? '0' : '') + date.getSeconds();
      const time = `${hours}:${minutes}:${seconds}`;
      const diffTime = (newDate - oldDate) / 1000;
      const diffPass4In = (newPass4In - oldPass4In) / diffTime / 1024 / 1024;
      const diffPass4Out = -(newPass4Out - oldPass4Out) / diffTime / 1024 / 1024;
      const diffPass6In = (newPass6In - oldPass6In) / diffTime / 1024 / 1024;
      const diffPass6Out = -(newPass6Out - oldPass6Out) / diffTime / 1024 / 1024;
      const diffBlock4In = (newBlock4In - oldBlock4In) / diffTime / 1024 / 1024;
      const diffBlock4Out = (newBlock4Out - oldBlock4Out) / diffTime / 1024 / 1024;
      const diffBlock6In = (newBlock6In - oldBlock6In) / diffTime / 1024 / 1024;
      const diffBlock6Out = (newBlock6Out - oldBlock6Out) / diffTime / 1024 / 1024;
      const point = {
        date: date,
        time: time,
        pass4in: diffPass4In,
        pass4out: diffPass4Out,
        pass6in: diffPass6In,
        pass6out: diffPass6Out,
        block4in: diffBlock4In,
        block4out: diffBlock4Out,
        block6in: diffBlock6In,
        block6out: diffBlock6Out,
      };

      if (oldHistory.length > historyLength) {
        oldHistory.shift();
      }

      ifaces[name].history = [...oldHistory, point];
    });
    return ifaces;
  }, {});

  useJsonUpdates(pfInterfacesURL, updateInterfaces, updateTime);

  if (Object.keys(interfaces).length == 0) {
    return (
      <Spin>
        <Card style={{margin: "30px"}}></Card>
      </Spin>);
  }

  const ifaceSort = Object.values(interfaces).sort((a, b) => {
    const aTraffic = a.in4pass + a.in6pass + a.out4apss + a.out6pass;
    const bTraffic = b.in4pass + b.in6pass + b.out4pass + b.out6pass;
    if (aTraffic > bTraffic) {
      return -1;
    }
    return 1;
  });

  return (
    <div style={{marginBottom: "12px"}}>
      {ifaceSort.map(iface => {
        const name = iface.interface;
        return (<PfInterface iface={iface} key={name} />);
      })}
    </div>
  );
}

export default PfInterfaces;
