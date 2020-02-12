import React, { useState, useEffect, useReducer } from 'react';
import { Card, Statistic, Col, Row, Descriptions, Typography, Divider, Spin } from 'antd';
import { ResponsiveContainer, ComposedChart, Bar, AreaChart, Area, LineChart, Line, CartesianGrid, XAxis, YAxis, Tooltip, Legend } from 'recharts';
import { getJSON, useJsonUpdates } from '../helpers.js';
import { serverURL } from '../config.js';
import './PfInterfaces.css';
import { formatTimeStr } from 'antd/lib/statistic/utils';

const pfInterfacesURL = `${serverURL}/api/pf-interfaces`;
const updateTime = 3000;
const diffTime = updateTime / 1000;

function PfInterfaces(props) {
  const [interfaces, updateInterfaces] = useReducer((state, update) => {
    let ifaces = {};
    update.forEach(iface => {
      const name = iface.interface;
      ifaces[name] = iface;
      const newPass4In = iface.in4pass.bytes;
      const newPass4Out = iface.out4pass.bytes;
      const newPass6In = iface.in6pass.bytes;
      const newPass6Out = iface.out6pass.bytes;
      const newBlock4In = iface.in4block.bytes;
      const newBlock4Out = iface.out4block.bytes;
      const newBlock6In = iface.in6block.bytes;
      const newBlock6Out = iface.out6block.bytes;
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
      const diffPass4In = Number(((newPass4In - oldPass4In) / diffTime / 1024 / 1024).toFixed(2));
      const diffPass4Out = Number((-(newPass4Out - oldPass4Out) / diffTime / 1024 / 1024).toFixed(2));
      const diffPass6In = Number(((newPass6In - oldPass6In) / diffTime / 1024 / 1024).toFixed(2));
      const diffPass6Out = Number((-(newPass6Out - oldPass6Out) / diffTime / 1024 / 1024).toFixed(2));
      const diffBlock4In = Number(((newBlock4In - oldBlock4In) / diffTime / 1024 / 1024).toFixed(2));
      const diffBlock4Out = Number(((newBlock4Out - oldBlock4Out) / diffTime / 1024 / 1024).toFixed(2));
      const diffBlock6In = Number(((newBlock6In - oldBlock6In) / diffTime / 1024 / 1024).toFixed(2));
      const diffBlock6Out = Number(((newBlock6Out - oldBlock6Out) / diffTime / 1024 / 1024).toFixed(2));
      const date = new Date();
      const time = date; // `${date.getHours()}:${date.getMinutes()}:${date.getSeconds()}`; // date;
      const point = {
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

      if (oldHistory.length > 60) {
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

  return (
    <div style={{marginBottom: "12px"}}>
      {Object.keys(interfaces).map(name => {
        const iface = interfaces[name];
        return (<PfInterface iface={iface} />);
      })}
    </div>
  );
}

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
      <ComposedChart data={iface.history}>
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
          formatter={(value, name, props) => {
            const abs = Math.abs(value);
            if (value < 1024) {
              return `${abs} MB/s`;
            } else {
              return `${abs/1024} GB/s`;
            }
          }}
        />
        <Legend />
        <CartesianGrid strokeDasharray="3 3" />
        <XAxis dataKey="time" />
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
        <Row>
          <Col xl={6} span={12}><Statistic title="References (States)" value={iface.references.states}/></Col>
          <Col xl={6} span={12}><Statistic title="References (Rules)" value={iface.references.rules}/></Col>
          <Col xl={12} span={24}><Typography>Counters last cleared {iface.cleared}</Typography></Col>
        </Row>
        <Divider />
        {ipv4Stats}
        <Divider />
        {ipv6Stats}
        <Divider />
        {(ipv4 || ipv6) ? graph : ""}
      </Card>
    </Col>
  );
}

export default PfInterfaces;
