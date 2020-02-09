import React, { useState, useEffect, useReducer } from 'react';
import { Card, Statistic, Col, Row, Descriptions, Typography, Divider, Spin } from 'antd';
import { ResponsiveLine, ResponsiveLineCanvas } from '@nivo/line';
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
      let old4In;
      let old4Out;
      let oldHistory4In;
      let oldHistory4Out;
      if (!state || state === {} || !state[name]) {
        old4In = new4In;
        old4Out = new4Out;
        oldHistory4In = [];
        oldHistory4Out = [];
      } else {
        old4In = state[name].in4pass.bytes;
        old4Out = state[name].out4pass.bytes;
        oldHistory4In = state[name].history.ipv4.in;
        oldHistory4Out = state[name].history.ipv4.out;
      }
      const diff4In = (new4In - old4In) / diffTime / 1024 / 1024;
      const diff4Out = -(new4Out - old4Out) / diffTime / 1024 / 1024;
      const date = new Date();
      const time = date; //`${date.getHours()}:${date.getMinutes()}:${date.getSeconds()}`;
      const point4In = { x: time, y: diff4In };
      const point4Out = { x: time, y: diff4Out };

      if (oldHistory4In.length > 60) {
        oldHistory4In.shift();
        oldHistory4Out.shift();
      }

      ifaces[name].history = {};
      ifaces[name].history.ipv4 = {};
      ifaces[name].history.ipv4.in = [...oldHistory4In, point4In];
      ifaces[name].history.ipv4.out = [...oldHistory4Out, point4Out];     // TODO: Maximum history length, grows without limit
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
              <div style={{width: "100%", height: 240}}>
                <ResponsiveLineCanvas
                  data={[
                    {
                      id: "out",
                      data: iface.history.ipv4.out
                    },
                    {
                      id: "in",
                      data: iface.history.ipv4.in
                    }]}
                  yScale={{
                    type: "linear",
                    stacked: false,
                    min: "auto",
                    max: "auto"
                  }}
                  animate
                  enablePoints={false}
                  enableArea={true}
                  margin={{
                    top: 10,
                    bottom: 65,
                    right: 10,
                    left: 70,
                  }}
                  axisLeft={{
                    enable: true,
                    tickSize: 2,
                    tickPadding: 4,
                    tickRotation: 0,
                    legend: "speed (MB/s)",
                    legendOffset: -60,
                    legendPosition: "middle"
                  }}
                  axisBottom={{
                    enable: true,
                    tickSize: 4,
                    tickPadding: 5,
                    tickRotation: -35,
                    legend: "time",
                    legendOffset: 55,
                    legendPosition: "middle",
                    format: "%H:%M:%S",
                  }}
                  xScale={{
                    type: "time"
                  }}
                  xFormat={date => `${date.getHours()}:${date.getMinutes()}:${date.getSeconds()}`}
                />
              </div>
            </Card>
          </Col>
        );
      })}
    </div>
  );
}

export default PfInterfaces;
