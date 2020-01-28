import React, { useState, useEffect } from 'react';
import { Table, Badge, Tooltip, Typography } from 'antd';
import { getJSON, useJsonUpdates, timeSince } from '../helpers.js';
import { serverURL } from '../config.js';
import './Processes.css';

const processURL = `${serverURL}/api/processes`;
const updateTime = 3000;

const { Text } = Typography;

function hmToSeconds(time) {
  const [hours, minutes] = time.split(":");
  return Number(hours) * 60 + Number(minutes);
}

function Processes() {
  const [processes, setProcesses] = useState();
  const [highlightedProc, setHighlightedProc] = useState();

  useJsonUpdates(processURL, setProcesses, updateTime);

  const columns = [
    {
      title: "User",
      dataIndex: "user",
    },
    {
      title: "Group",
      dataIndex: "group",
    },
    {
      title: "PID",
      dataIndex: "pid",
      render: pid => {
        const highlighted = highlightedProc === pid;
        return (<span style={{padding: 3, backgroundColor: highlighted ? "orange" : null, borderRadius: 3}}>{pid}</span>);
      }
    },
    {
      title: "PPID",
      dataIndex: "parentPid",
      render: ppid => {
        const handleMouseEnter = () => setHighlightedProc(ppid);
        const handleMouseLeave = () => setHighlightedProc(null);
        return (<span onMouseEnter={handleMouseEnter} onMouseLeave={handleMouseLeave}>{ppid}</span>);
      }
    },
    {
      title: "Stats",
      dataIndex: "stat",
      render: stats => (
        stats.map(stat => {
          const text = stat.replace("_", " ");
          let color;
          switch(stat) {
          case "idle":
            color = "geekblue";
            break;
          case "uninterruptible":
            color = "purple";
            break;
          case "runnable":
            color = "green";
            break;
          case "sleeping":
            color = "cyan";
            break;
          case "stopped":
            color = "red";
            break;
          case "zombie":
            color = "black";
            break;
          case "raised_priority":
            color = "yellow";
            break;
          case "reduced_priority":
            color = "brown";
            break;
          case "pledged":
            color = "orange";
            break;
          case "unveil_locked":
            color = "purple";
            break;
          case "unveil_not_locked":
            color = "lavender";
            break;
          case "session_leader":
            color = "#ccc";
            break;
          case "foreground":
            color = "grey";
            break;
          default:
            color = "#333";
          }
          return (
            <Tooltip title={text}>
              <Badge color={color} />
            </Tooltip>
          );
        })
      )
    },
    {
      title: "%CPU",
      dataIndex: "percentCPU",
      sorter: (a, b) => a.percentCPU - b.percentCPU,
    },
    {
      title: "%MEM",
      dataIndex: "percentMemory",
      sorter: (a, b) => a.percentMemory - b.percentMemory,
    },
    {
      title: "VSZ",
      dataIndex: "virtualMemorySize"
    },
    {
      title: "RSS",
      dataIndex: "residentSetSize"
    },
    {
      title: "Nice",
      dataIndex: "nice"
    },
    {
      title: "Pri",
      dataIndex: "priority"
    },
    {
      title: "WChan",
      dataIndex: "waitChannel"
    },
    {
      title: "Started",
      dataIndex: "started",
      sorter: (a, b) => new Date(a.started) - new Date(b.started),
      render: started => {
        const time = timeSince(started);
        return (
          <Tooltip title={started}>
            <Text>
              {time.days ? time.days + ":" : null}
              {time.hours ? time.hours + ":" : null}
              {String(time.minutes).padStart(2, '0')}:{String(time.seconds).padStart(2, '0')}</Text>
          </Tooltip>
        );
      }
    },
    {
      title: "Time",
      dataIndex: "time",
      sorter: (a, b) => {
        return hmToSeconds(a.time) - hmToSeconds(b.time);
      },
    },
    // {
    //   title: "Terminal",
    //   dataIndex: "terminal"
    // },
    {
      title: "Command",
      dataIndex: "command",
      render: proc => (<Text code>{proc}</Text>)
    }
  ];

  return (
    <div className="processes" style={{padding: "24px 24px 0 24px", backgroundColor: "white"}}>
      <Table
        dataSource={processes}
        columns={columns}
        rowKey="pid"
        loading={!processes}
        size="small"
        scroll={{x: true}}
        pagination={false}
      />
    </div>
  );
}

export default Processes;
