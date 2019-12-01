import React, { useState, useEffect } from 'react';
import { Tag, Table, Typography, Icon } from 'antd';
import { getJSON } from '../helpers.js';
import { serverURL } from '../config.js';
import './PfStates.css';

const { Text } = Typography;

const pfStatesURL = `${serverURL}/api/pf-states`;
const updateTime = 5000;

function PfStates() {
  const [states, setStates] = useState([]);
  const [filteredInfo, setFilteredInfo] = useState({});
  const [sortedInfo, setSortedInfo] = useState({});

  useEffect(() => {
    getJSON(pfStatesURL).then(res => setStates(res));
    const interval = setInterval(() => {
      getJSON(pfStatesURL).then(res => setStates(res));
    }, updateTime);

    return () => {
      clearInterval(interval);
    };
  }, []);

  const handleChange = (pagination, filters, sorter) => {
    console.log("parameters", pagination, filters, sorter);
    setFilteredInfo(filters);
    setSortedInfo(sorter);
  };

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
        return (<span>{direction.toUpperCase()}</span>);
      }
    },
    {
      title: "Source",
      dataIndex: "sourceIP",
      width: "23em",
      align: "right",
      render: src => (<Text code>{src}</Text>)
    },
    {
      title: "Port",
      dataIndex: "sourcePort",
      width: "5em",
      render: prt => (<Text code>{prt}</Text>)
    },
    {
      title: "Destination",
      dataIndex: "destinationIP",
      align: "right",
      width: "23em",
      render: dst => (<Text code>{dst}</Text>)
    },
    {
      title: "Port",
      dataIndex: "destinationPort",
      width: "5em",
      render: prt => (<Text code>{prt}</Text>)
    },
    {
      title: "Age",
      dataIndex: "age",
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
      render: state => (<Text code>{state}</Text>)
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
      render: state => (<Text code>{state}</Text>)
    },
    {
      title: "Packets",
      dataIndex: "packetsSent",
    },
    {
      title: "Rule",
      dataIndex: "rule",
      render: rule => {
        const num = rule === -1 ? "*" : rule;
        return num;
      }
    }
  ];

  return (<Table
            columns={columns}
            dataSource={states}
            pagination
            size="small"
            rowKey="id"
            scroll={{x: true}}
            expandedRowRender={row => {
              const gateway = row.gateway
                    ? (<span><strong>Gateway: </strong><Text code>{row.gateway}</Text></span>)
                    : "";
              const expires = (<span><strong>Expires: </strong><Text code>{row.expires}</Text></span>);
              return (<p style={{margin: 0}}>{gateway} {expires}</p>);
            }}
            pagination={{pageSize: 18}}
          />);

  return (
    <div className="pfstates">
      <table>
        <thead>
          <tr>
            <th className="proto">Proto</th>
            <th>Direction</th>
            <th className="ip">Source</th>
            <th className="ip">Destination</th>
            <th>State</th>
            <th>Age</th>
            <th>Expires</th>
            <th>Packets</th>
            <th>Bytes</th>
            <th>Rule</th>
            <th>Gateway</th>
          </tr>
        </thead>
        <tbody>
          {states.map(state => {
            let bg = "none";
            let fg = "black";
            let style = {};
            let rule;
            if (state.proto.includes("tcp")) {
              bg = "#d5f3fd";
            }
            if (state.proto.includes("udp")) {
              bg = "#ffecec";
            }
            if (state.rule === -1) {
              rule = "*";
            } else {
              rule = state.rule;
            }
            if ((state.sourceState + state.destinationState).includes("NO_TRAFFIC")) {
              fg = "grey";
            }
            style.backgroundColor = bg;
            style.color = fg;
            return (
              <tr style={style} key={state.id}>
              <td>{state.proto}</td>
              <td>{state.direction}</td>
              <td>{`${state.sourceIP}:${state.sourcePort}`}</td>
              <td>{`${state.destinationIP}:${state.destinationPort}`}</td>
              <td>{`${state.sourceState}:${state.destinationState}`}</td>
              <td>{state.age}</td>
              <td>{state.expires}</td>
              <td>{`${state.packetsSent}:${state.packetsReceived}`}</td>
              <td>{`${state.bytesSent}:${state.bytesReceived}`}</td>
              <td>{rule}</td>
              <td>{state.gateway}</td>
            </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export default PfStates;
