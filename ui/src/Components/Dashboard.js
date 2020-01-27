import React, { useState } from 'react';
import { Card, Typography, Row, Col, Progress, Tooltip, Spin } from 'antd';
import { getJSON, useJsonUpdates } from '../helpers';
import { serverURL } from '../config';

const { Text, Title } = Typography;

const unameURL = `${serverURL}/api/uname`;
const uptimeURL = `${serverURL}/api/uptime`;
const ramURL = `${serverURL}/api/ram`;
const vmstatURL = `${serverURL}/api/vmstat`;
const diskUsageURL = `${serverURL}/api/disk-usage`;
const swapUsageURL = `${serverURL}/api/swap-usage`;
const cpuStatesURL = `${serverURL}/api/cpu-states`;
const updateTime = 5000;

function Uname(props) {
  const [uname, setUname] = useState();
  useJsonUpdates(unameURL, setUname, updateTime);

  return (
    <Card>
      <Title>{uname ? uname.nodeName : ""}</Title>
      <Text>{uname ? `${uname.osName} ${uname.osRelease} (${uname.hardware})` : ""}</Text>
    </Card>
  );
}

function Uptime(props) {
  const [uptime, setUptime] = useState();
  useJsonUpdates(uptimeURL, setUptime, updateTime);

  return (
    <Card>
      <Text>Time: {uptime ? uptime.time : ""}</Text><br/>
      <Text>Uptime: {uptime ? uptime.uptime : ""}</Text><br/>
      <Text>Users: {uptime ? uptime.users : ""}</Text><br/>
      <Text>Load Avg.: {uptime ? uptime.loadAvg.join(", ") : ""}</Text>
    </Card>
  );
}

function Ram(props) {
  const [ram, setRam] = useState();
  useJsonUpdates(ramURL, setRam, updateTime);

  if (!ram) {
    return (<Spin><Card><div style={{width: 120, height: 120}}/></Card></Spin>);
  }

  const total = ram.total;
  const active = ram.active;
  const free = ram.free;
  const other = ram.total - (ram.free + ram.active);
  const percentUsed = Number(((total - free) / total * 100).toFixed(2));
  const percentActive = Number((active / total * 100).toFixed(2));

  return (
    <Card title="RAM">
      <Tooltip title={<div style={{textAlign: "center"}}>{active} MB Active + {other} MB Other <br/> / {total}M Total</div>}>
        <Progress percent={percentUsed} successPercent={percentActive} type="dashboard"/>
      </Tooltip>
    </Card>
  );
}

function CpuUsage(props) {
  const [cpuStates, setCpuStates] = useState({old: {}, new: {user: 0, nice: 0, sys: 0, spin: 0, interrupt: 0, idle: 0}});

  const handleCpuStateChange = newState => {
    setCpuStates(state => ({
      old: state.new,
      new: newState
    }));
  };

  useJsonUpdates(cpuStatesURL, handleCpuStateChange, updateTime);

  const stateDiff = {
    user: cpuStates.new.user - cpuStates.old.user,
    nice: cpuStates.new.nice - cpuStates.old.nice,
    sys: cpuStates.new.sys - cpuStates.old.sys,
    spin: cpuStates.new.spin - cpuStates.old.spin,
    interrupt: cpuStates.new.interrupt - cpuStates.old.interrupt,
    idle: cpuStates.new.idle - cpuStates.old.idle,
  };
  const user = stateDiff.user + stateDiff.nice;
  const system = stateDiff.sys + stateDiff.spin + stateDiff.interrupt;
  const idle = stateDiff.idle;
  const total = user + system + stateDiff.idle;
  const userPercent = Number((user / total * 100).toFixed(2));
  const systemPercent = Number((system / total * 100).toFixed(2));
  const usagePercent = Number((userPercent + systemPercent).toFixed(2));
  const idlePercent = Number((idle / total * 100).toFixed(2));

  return (
    <Card title="CPU">
      <Tooltip title={<div>User: {userPercent}% <br/> System: {systemPercent}%</div>}>
        <Progress percent={usagePercent} successPercent={userPercent} type="dashboard" />
      </Tooltip>
    </Card>
  );
};

function VmStat(props) {
  const [vmstat, setVmstat] = useState();
  useJsonUpdates(vmstatURL, setVmstat, updateTime);

  return (
    <>
      <Card>
        <Text>Procs Running: {vmstat ? vmstat.procs.running : ""}</Text><br/>
        <Text>Procs Sleeping: {vmstat ? vmstat.procs.sleeping : ""}</Text><br/>
      </Card>
    </>
  );
}

function DiskUsage(props) {
  const [diskUsage, setDiskUsage] = useState();
  useJsonUpdates(diskUsageURL, setDiskUsage, updateTime);

  return (
    <Card title="Disk Usage">
      {diskUsage ? diskUsage.filesystems.map(disk => {
        const used = Number((diskUsage.blockSize * disk.used / 1024 / 1024 / 1024).toFixed(2));
        const totalSize = Number((diskUsage.blockSize * disk.blocks / 1024 / 1024 / 1024).toFixed(2));
        return (
          <Card.Grid key={disk.mountPoint}>
            <Text strong>{disk.mountPoint}</Text><br/>
            <Tooltip title={`${used} GB / ${totalSize} GB`}>
              <Progress percent={disk.capacity}/>
            </Tooltip>
          </Card.Grid>
        );
      }) : ""}
    </Card>
  );
}

function SwapUsage(props) {
  const [swapUsage, setSwapUsage] = useState();
  useJsonUpdates(swapUsageURL, setSwapUsage, updateTime);

  return (
    <>
      {swapUsage ? swapUsage.devices.map(device => (
        <Card key={device.device}>
          <Text>Device: {device.device}</Text><br/>
          <Text>Blocks: {device.blocks}</Text><br/>
          <Text>Used: {device.used}</Text><br/>
          <Text>Available: {device.available}</Text><br/>
          <Text>Capacity: {device.capacity}</Text><br/>
          <Text>Priority: {device.priority}</Text><br/>
        </Card>
      )) : ""}
    </>
  );
}

function Dashboard(props) {
  return (
    <div>
      <Row>
        <Col span={8}>
          <Uname/>
        </Col>
      </Row>
      <Row>
        <Col span={8}>
          <Uptime/>
        </Col>
      </Row>
      <Row><Ram/></Row>
      <Row><CpuUsage/></Row>
      <Row><VmStat/></Row>
      <Row><DiskUsage/></Row>
      <Row><SwapUsage/></Row>
    </div>
  );
}

export default Dashboard;
