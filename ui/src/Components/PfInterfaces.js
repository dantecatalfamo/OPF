import React, { useState, useEffect } from 'react';
import { Card, Statistic, Col, Row, Descriptions, Typography, Divider, Spin } from 'antd';
import { getJSON } from '../helpers.js';
import { serverURL } from '../config.js';
import './PfInterfaces.css';

const pfInterfacesURL = `${serverURL}/api/pf-interfaces`;
const updateTime = 2000;

function PfStates() {
  const [interfaces, setInterfaces] = useState([]);

  useEffect(() => {
    getJSON(pfInterfacesURL).then(res => setInterfaces(res));
    const interval = setInterval(() => {
      getJSON(pfInterfacesURL).then(res => setInterfaces(res));
    }, updateTime);

    return () => {
      clearInterval(interval);
    };
  }, []);

  if (interfaces.length == 0) {
    return (
      <Spin>
        <Card style={{margin: "30px"}}></Card>
      </Spin>);
  }

  return (
    <div style={{marginBottom: "12px"}}>
      {interfaces.map(iface => {
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
          <Col xxl={{span: 18, offset: 3}}
               xl={{span: 20, offset: 2}}
               lg={{span: 24}}>
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
            </Card>
          </Col>
        );
      })}
    </div>
  );

  return (
    <div className="pfinterfaces">
      <table>
        <thead>
          <tr>
            <th>Interface</th>
            <th>Cleared</th>
            <th>References (States/Rules)</th>
            <th>In Pass (IPv4)</th>
            <th>In Block (IPv4)</th>
            <th>Out Pass (IPv4)</th>
            <th>Out Block (IPv4)</th>
            <th>In Pass (IPv6)</th>
            <th>In Block (IPv6)</th>
            <th>Out Pass (IPv6)</th>
            <th>Out Block (IPv6)</th>
          </tr>
        </thead>
        <tbody>
          {interfaces.map(iface => (
            <tr key={iface.interface}>
              <td className="left">{iface.interface}</td>
              <td className="left">{iface.cleared}</td>
              <td>{`${iface.references.states}/${iface.references.rules}`}</td>
              <td>{`${iface.in4pass.packets}/${iface.in4pass.bytes}`}</td>
              <td>{`${iface.in4block.packets}/${iface.in4block.bytes}`}</td>
              <td>{`${iface.out4pass.packets}/${iface.out4pass.bytes}`}</td>
              <td>{`${iface.out4block.packets}/${iface.out4block.bytes}`}</td>
              <td>{`${iface.in6pass.packets}/${iface.in6pass.bytes}`}</td>
              <td>{`${iface.in6block.packets}/${iface.in6block.bytes}`}</td>
              <td>{`${iface.out6pass.packets}/${iface.out6pass.bytes}`}</td>
              <td>{`${iface.out6block.packets}/${iface.out6block.bytes}`}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default PfStates;
