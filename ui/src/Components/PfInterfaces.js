import React, { useState, useEffect, useReducer } from 'react';
import { Card, Statistic, Col, Row, Descriptions, Typography, Divider, Spin } from 'antd';
import { ResponsiveContainer, AreaChart, Area, LineChart, Line, CartesianGrid, XAxis, YAxis, Tooltip } from 'recharts';
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
      const new4In = iface.in4pass.bytes;
      const new4Out = iface.out4pass.bytes;
      const new6In = iface.in6pass.bytes;
      const new6Out = iface.out6pass.bytes;
      let old4In;
      let old4Out;
      let old6In;
      let old6Out;
      let oldHistory;
      if (!state || state === {} || !state[name]) {
        old4In = new4In;
        old4Out = new4Out;
        old6In = new6In;
        old6Out = new6Out;
        oldHistory = [];
      } else {
        old4In = state[name].in4pass.bytes;
        old4Out = state[name].out4pass.bytes;
        old6In = state[name].in6pass.bytes;
        old6Out = state[name].out6pass.bytes;
        oldHistory = state[name].history;
      }
      const diff4In = Number(((new4In - old4In) / diffTime / 1024 / 1024).toFixed(2));
      const diff4Out = Number((-(new4Out - old4Out) / diffTime / 1024 / 1024).toFixed(2));
      const diff6In = Number(((new6In - old6In) / diffTime / 1024 / 1024).toFixed(2));
      const diff6Out = Number((-(new6Out - old6Out) / diffTime / 1024 / 1024).toFixed(2));
      const date = new Date();
      const time = date; // `${date.getHours()}:${date.getMinutes()}:${date.getSeconds()}`; // date;
      const point = {
        time: time,
        in4: diff4In,
        out4: diff4Out,
        in6: diff6In,
        out6: diff6Out,
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

        const testData = [{x: 1, y: 1}, {x: 2, y: 3}];

        return (
          <Col
            key={name}
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
              {/* {graph} */}
              <Divider />
              <ResponsiveContainer height={250}>
                <AreaChart data={iface.history}>
                  <Area
                    dataKey="in4"
                    name="IPv4 In"
                    isAnimationActive={false}
                    stroke="green"
                    fill="green"
                    stackId="in"
                  />
                  <Area
                    dataKey="in6"
                    name="IPv6 In"
                    isAnimationActive={false}
                    stroke="lightgreen"
                    fill="lightgreen"
                    stackId="in"
                  />
                  <Area
                    dataKey="out4"
                    name="IPv4 Out"
                    isAnimationActive={false}
                    stroke="red"
                    fill="red"
                    stackId="out"
                  />
                  <Area
                    dataKey="out6"
                    name="IPv6 Out"
                    isAnimationActive={false}
                    stroke="pink"
                    fill="pink"
                    stackId="out"
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
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="time" />
                  <YAxis />
                </AreaChart>
              </ResponsiveContainer>
            </Card>
          </Col>
        );
      })}
    </div>
  );
}

export default PfInterfaces;
