import React, { useState } from 'react';
import { Card, Col, Descriptions, Divider, Row, Badge } from 'antd';
import { serverURL } from '../config';
import { useJsonUpdates } from '../helpers';

const wireguardURL = `${serverURL}/api/wireguard-interfaces`;

export default function Wireguard() {
  const [wgInterfaces, setWgInterfaces] = useState<any[]>([]);
  useJsonUpdates(wireguardURL, setWgInterfaces, 5 * 1000);
  const ifaces = wgInterfaces.map((iface) => {
    const flags = iface.flags.replace(/(.*\<)|\>/g, '').split(',');
    const isUp = flags.includes('UP');
    const addrs = iface.addresses.map((addr: any) => `${addr.address}/${addr.netmask}`).join(', ');
    const peers = iface.peers.map((peer: any) => {
      return (
        <Col span={24} xl={{span: 12}}>
          <Card title={peer.publicKey} type="inner">
            <Descriptions size="small" column={4}>
              <Descriptions.Item span={2} label="Endpoint">{peer.endpointAddress ? `${peer.endpointAddress}:${peer.endpointPort}` : '<Not connected>'}</Descriptions.Item>
                <Descriptions.Item span={2} label="Last Handshake">{`${peer.lastHandshake} seconds`}</Descriptions.Item>
                <Descriptions.Item span={2} label="Transmitted">{`${peer.transmitted} bytes`}</Descriptions.Item>
                <Descriptions.Item span={2} label="Received">{`${peer.received} bytes`}</Descriptions.Item>
                <Descriptions.Item span={4} label="Allowed IPs">{peer.allowedIPs.join(', ')}</Descriptions.Item>
            </Descriptions>
          </Card>
        </Col>
      );
    });

    return (
      <Card title={<span><Badge status={isUp ? 'success' : 'error'}/>{iface.name}</span>}>
        <Descriptions column={4}>
          <Descriptions.Item span={2} label="Public Key">{iface.publicKey}</Descriptions.Item>
          <Descriptions.Item span={1} label="Addresses">{addrs}</Descriptions.Item>
          <Descriptions.Item span={1} label="Port">{iface.port}</Descriptions.Item>
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
