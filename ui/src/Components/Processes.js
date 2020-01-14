import React, { useState, useEffect } from 'react';
import { Table, Badge, Tooltip } from 'antd';
import { getJSON } from '../helpers.js';
import { serverURL } from '../config.js';
import './Process.css';


const processURL = `${serverURL}/api/processes`;
const updateTime = 3000;

function Processes() {
  const [processes, setProcesses] = useState();

  useEffect(() => {
    getJSON(processURL).then(res => setProcesses(res));
    const interval = setInterval(() => {
      getJSON(processURL).then(res => setProcesses(res));
    }, updateTime);

    return () => {
      clearInterval(interval);
    };
  }, []);

  const columns = [
    {
      title: "User",
      dataIndex: "user",
    },
    {
      title: "Group",
      dataIndex: "group"
    },
    {
      title: "PID",
      dataIndex: "pid"
    },
    {
      title: "PPID",
      dataIndex: "parentPid"
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
      dataIndex: "percentCPU"
    },
    {
      title: "%MEM",
      dataIndex: "percentMemory"
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
      dataIndex: "started"
    },
    {
      title: "Time",
      dataIndex: "time"
    },
    {
      title: "Terminal",
      dataIndex: "terminal"
    },
    {
      title: "Command",
      dataIndex: "command"
    }
  ];

  return (
    <div style={{padding: "24px 24px 0 24px", backgroundColor: "white"}}>
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
