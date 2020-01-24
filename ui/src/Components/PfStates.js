import React, { useState, useEffect, useLayoutEffect } from 'react';
import { Tag, Table, Typography, Icon, Card, Input, InputNumber, Button, Popover } from 'antd';
import { getJSON, useWindowSize } from '../helpers.js';
import { serverURL } from '../config.js';
import './PfStates.css';

const { Text } = Typography;

const pfStatesURL = `${serverURL}/api/pf-states`;
const updateTime = 5000;

function ipLookupButton(ip) {
  const whatismyipButton = (
    <Button
      href={`https://www.whatismyip.com/${ip}/`}
      target="_blank"
      size="small"
    >whatismyip.com</Button>
  );
  return (
    <Popover
      trigger="click"
      placement="bottom"
      content={whatismyipButton}
    >
      <Text code>{ip}</Text>
    </Popover>
  );
}

function portLookupButton(port) {
  const speedguideButton = (
    <Button
      href={`https://www.speedguide.net/port.php?port=${port}`}
      target="_blank"
      size="small"
    >speedguide.net</Button>
  );
  return (
    <Popover
      trigger="click"
      placement="bottom"
      content={speedguideButton}
    >
      <Text code>{port}</Text>
    </Popover>
  );
}

function filterDialog(placeholder) {
  return ({setSelectedKeys, selectedKeys, confirm, clearFilters}) => {
    return (
      <div style={{padding: 8}}>
        <Input
          placeholder={placeholder}
          value={selectedKeys[0]}
          onChange={e => setSelectedKeys(e.target.value ? [e.target.value] : [])}
          onPressEnter={() => confirm()}
          style={{width: 188, marginBottom: 8, display: 'block'}}
        />
        <Button
          type="primary"
          size="small"
          icon="search"
          onClick={confirm}
          style={{width: 90, marginRight: 8}}
        >Search</Button>
        <Button
          onClick={clearFilters}
          size="small"
          style={{width: 90}}
        >Reset</Button>
      </div>
    );
  };
};

function expandedRow(row) {
  let gateway;
  if (row.gateway) {
    gateway = (
      <>
        <td><strong>Gateway</strong></td>
        <td><Text code>{row.gateway}</Text></td>
      </>
    );}
  return (
    <div>
      <table style={{width: "max-content", minWidth: "max-content"}}>
        <tbody>
          <tr>
            <td align="right"><strong>Packets Sent</strong></td>
            <td><Text code>{row.packetsSent}</Text></td>
            <td align="right"><strong>Packets Received</strong></td>
            <td><Text code>{row.packetsReceived}</Text></td>
            <td align="right"><strong>Expires</strong></td>
            <td><Text code>{row.expires}</Text></td>
          </tr>
          <tr>
            <td align="right"><strong>Bytes Sent</strong></td>
            <td><Text code>{row.bytesSent}</Text></td>
            <td align="right"><strong>Bytes Received</strong></td>
            <td><Text code>{row.bytesReceived}</Text></td>
            {gateway}
          </tr>
        </tbody>
      </table>
    </div>
  );
}

function PfStates() {
  const [windowWidth, windowHeight] = useWindowSize();
  const [states, setStates] = useState();
  const [filteredInfo, setFilteredInfo] = useState({});
  const [sortedInfo, setSortedInfo] = useState({});
  const [tableRows, setTableRows] = useState(10);

  useLayoutEffect(() => {
    // total space - top bar - padding top
    const paddingTop = 24;
    const topBar = 64;
    const tableHeader = 38;
    const horizontalScrollBar = 12; // rough guess
    const pagination = 16 + 24 + 16;
    const usedSpace = paddingTop + topBar + tableHeader + horizontalScrollBar + pagination;
    const usableSpace = windowHeight - usedSpace;
    const rows = Math.floor(usableSpace / 40);
    setTableRows(rows);
  }, [windowHeight]);

  useEffect(() => {
    getJSON(pfStatesURL).then(res => setStates(res));
    const interval = setInterval(() => {
      getJSON(pfStatesURL).then(res => setStates(res));
    }, updateTime);

    return () => {
      clearInterval(interval);
    };
  }, []);

  const columns = [
    {
      title: "Protocol",
      dataIndex: "proto",
      width: "7em",
      filters: [
        { text: "UDP", value: "udp" },
        { text: "TCP", value: "tcp" },
        { text: "ICMP", value: "icmp" },
        { text: "IPV6-ICMP", value: "ipv6-icmp" },
      ],
      onFilter: (value, record) => record.proto === value,
      render: proto => {
        let color;
        if (proto === "tcp") { color = "blue"; }
        if (proto === "udp") { color = "red"; }
        return (<Tag color={color}>{proto.toUpperCase()}</Tag>);
      }
    },
    {
      title: "Direction",
      dataIndex: "direction",
      width: "7em",
      filters: [
        { text: "IN", value: "in" },
        { text: "OUT", value: "out" }
      ],
      filterMultiple: false,
      onFilter: (value, record) => record.direction === value,
      render: direction => {
        let color;
        if (direction === "in")  { color = "SlateGray"; }
        return (<Tag color={color}>{direction.toUpperCase()}</Tag>);
      }
    },
    {
      title: "Source",
      dataIndex: "sourceIP",
      width: "23em",
      align: "right",
      onFilter: (value, record) => record.sourceIP.match(value),
      filterDropdown: filterDialog("Source Address"),
      render: src => ipLookupButton(src),
    },
    {
      title: "Port",
      dataIndex: "sourcePort",
      width: "5em",
      onFilter: (value, record) => record.sourcePort == value,
      filterDropdown: filterDialog("Source Port"),
      render: prt => portLookupButton(prt),
    },
    {
      title: "Destination",
      dataIndex: "destinationIP",
      align: "right",
      width: "23em",
      onFilter: (value, record) => record.destinationIP.match(value),
      filterDropdown: filterDialog("Destination Address"),
      render: dst => ipLookupButton(dst),
    },
    {
      title: "Port",
      dataIndex: "destinationPort",
      width: "5em",
      onFilter: (value, record) => record.destinationPort == value,
      filterDropdown: filterDialog("Destination Port"),
      render: prt => portLookupButton(prt),
    },
    {
      title: "Age",
      dataIndex: "age",
      sorter: (a, b) => a.age > b.age,
      render: age => (<Text code>{age}</Text>)
    },
    {
      title: "Source State",
      dataIndex: "sourceState",
      filters: [
        { text: "SINGLE", value: "SINGLE" },
        { text: "MULTIPLE", value: "MULTIPLE" },
        { text: "SYN_SENT", value: "SYN_SENT" },
        { text: "SYN_RCVD", value: "SYN_RCVD" },
        { text: "ESTABLISHED", value: "ESTABLISHED" },
        { text: "FIN_WAIT_1", value: "FIN_WAIT_1" },
        { text: "FIN_WAIT_2", value: "FIN_WAIT_2" },
        { text: "CLOSE_WAIT", value: "CLOSE_WAIT" },
        { text: "CLOSING", value: "CLOSING" },
      ],
      onFilter: (value, record) => record.sourceState === value,
      render: state => {
        let color;
        if (state === "SINGLE") { color = "orange"; }
        if (state === "MULTIPLE") { color = "red"; }
        if (state === "ESTABLISHED") { color = "blue"; }
        return (<Tag color={color}>{state}</Tag>);
      }
    },
    {
      title: "Destination State",
      dataIndex: "destinationState",
      filters: [
        { text: "SINGLE", value: "SINGLE" },
        { text: "MULTIPLE", value: "MULTIPLE" },
        { text: "NO_TRAFFIC", value: "NO_TRAFFIC" },
        { text: "SYN_SENT", value: "SYN_SENT" },
        { text: "SYN_RCVD", value: "SYN_RCVD" },
        { text: "ESTABLISHED", value: "ESTABLISHED" },
        { text: "FIN_WAIT_1", value: "FIN_WAIT_1" },
        { text: "FIN_WAIT_2", value: "FIN_WAIT_2" },
        { text: "CLOSE_WAIT", value: "CLOSE_WAIT" },
        { text: "CLOSING", value: "CLOSING" },
      ],
      onFilter: (value, record) => record.destinationState === value,
      render: state => {
        let color;
        if (state === "SINGLE") { color = "orange"; }
        if (state === "MULTIPLE") { color = "red"; }
        if (state === "NO_TRAFFIC") { color = "grey"; }
        if (state === "ESTABLISHED") { color = "blue"; }
        return (<Tag color={color}>{state}</Tag>);
      }
    },
    {
      title: "Packets",
      dataIndex: "packetsTotal",
      sorter: (a, b) => a.packetsTotal - b.packetsTotal,
      render: pkts => (<Text code>{pkts}</Text>)
    },
    {
      title: "Rule",
      dataIndex: "rule",
      onFilter: (value, record) => record.rule == (value === "*" ? -1 : value),
      filterDropdown: filterDialog("Rule"),
      render: rule => {
        const num = rule === -1 ? "*" : rule;
        return num;
      }
    }
  ];

  return (
    <div style={{padding: "24px 24px 0 24px", backgroundColor: "white"}}>
      <Table
        columns={columns}
        dataSource={states}
        pagination
        loading={!states}
        size="small"
        rowKey="id"
        scroll={{x: true}}
        pagination={{pageSize: tableRows}}
        expandedRowRender={row => expandedRow(row)}
      />
    </div>
  );
}

export default PfStates;
