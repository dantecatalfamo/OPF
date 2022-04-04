import React, { useState } from 'react';
import { Card, Col, Descriptions, Divider, Row } from 'antd';
import { serverURL } from '../config';
import { useJsonUpdates } from '../helpers';

const wireguardURL = `${serverURL}/api/wireguard-interfaces`;

export default function Wireguard() {
  const [wgInterfaces, setWgInterfaces] = useState<any[]>([]);
  useJsonUpdates(wireguardURL, setWgInterfaces, 5 * 1000);
  const ifaces = wgInterfaces.map((iface) => {
    const addrs = iface.addresses.map((addr: any) => `${addr.address}/${addr.netmask}`).join(', ');
    const peers = iface.peers.map((peer: any) => {
      return (
        <Col span={24}>
          <Descriptions bordered>
            <Descriptions.Item span={2} label="Public Key">{peer.publicKey}</Descriptions.Item>
            <Descriptions.Item label="Endpoint">{peer.endpointAddress ? `${peer.endpointAddress}:${peer.endpointPort}` : '<Not connected>'}</Descriptions.Item>
            <Descriptions.Item label="Transmitted">{`${peer.transmitted} bytes`}</Descriptions.Item>
            <Descriptions.Item label="Received">{`${peer.received} bytes`}</Descriptions.Item>
            <Descriptions.Item label="Last Handshake">{`${peer.lastHandshake} seconds`}</Descriptions.Item>
            <Descriptions.Item label="Allowed IPs">{peer.allowedIPs.join(', ')}</Descriptions.Item>
          </Descriptions>
        </Col>
      );
    });
    return (
      <Card title={iface.name}>
        <Descriptions bordered>
          <Descriptions.Item label="Public Key">{iface.publicKey}</Descriptions.Item>
          <Descriptions.Item label="Addresses">{addrs}</Descriptions.Item>
          <Descriptions.Item label="Port">{iface.port}</Descriptions.Item>
        </Descriptions>
        <Divider plain>Clients</Divider>
        <Row gutter={[4, 4]}>
          {peers}
        </Row>
      </Card>
    );
  });
  return (
    <Row>
      <Col xxl={{ span: 16, offset: 4 }}>
        {ifaces}
      </Col>
    </Row>
  );
}
