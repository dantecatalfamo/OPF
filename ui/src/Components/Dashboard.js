import React, { useState, useEffect } from 'react';
import { Card, Typography, Row, Col, Progress } from 'antd';
import { getJSON, useJsonUpdates } from '../helpers';
import { serverURL } from '../config';

const { Text, Title } = Typography;

const unameURL = `${serverURL}/api/uname`;
const uptimeURL = `${serverURL}/api/uptime`;
const vmstatURL = `${serverURL}/api/vmstat`;
const diskUsageURL = `${serverURL}/api/disk-usage`;
const swapUsageURL = `${serverURL}/api/swap-usage`;
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

function VmStat(props) {
  const [vmstat, setVmstat] = useState();
  useJsonUpdates(vmstatURL, setVmstat, updateTime);

  return (
    <>
      <Card>
        <Text>Procs Running: {vmstat ? vmstat.procs.running : ""}</Text><br/>
        <Text>Procs Sleeping: {vmstat ? vmstat.procs.sleeping : ""}</Text><br/>
        <Text>Memory Active: {vmstat ? vmstat.memory.active : ""}</Text><br/>
        <Text>Memory Free: {vmstat ? vmstat.memory.free : ""}</Text>
      </Card>
      <Card>
        <Text>Page Faults: {vmstat ? vmstat.page.faults : ""}</Text><br/>
        <Text>Page Reclaims: {vmstat ? vmstat.page.reclaims : ""}</Text><br/>
        <Text>Pages Paged In: {vmstat ? vmstat.page.pagedIn : ""}</Text><br/>
        <Text>Pages Paged Out: {vmstat ? vmstat.page.pagedOut : ""}</Text><br/>
        <Text>Pages Freed: {vmstat ? vmstat.page.freed : ""}</Text><br/>
        <Text>Page Scanned: {vmstat ? vmstat.page.scanned : ""}</Text>
      </Card>
      <Card>
        {vmstat ? vmstat.disks.map(disk => (
          <>
          <Text>Name: {disk.name}</Text><br/>
            <Text>Pages /s: {disk.transfers}</Text><br/>
          </>
        )) : ""}
      </Card>
      <Card>
        <Text>Interrupts: {vmstat ? vmstat.traps.interrupts : ""}</Text><br/>
        <Text>System Calls: {vmstat ? vmstat.traps.systemCalls : ""}</Text><br/>
        <Text>Context Switches: {vmstat ? vmstat.traps.contextSwitch : ""}</Text><br/>
      </Card>
      <Card title="CPU Usage">
        <Text>User: {vmstat ? vmstat.cpu.user : ""}</Text><br/>
        <Text>System: {vmstat ? vmstat.cpu.system : ""}</Text><br/>
        <Text>Idle: {vmstat ? vmstat.cpu.idle : ""}</Text><br/>
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
        const totalSize = diskUsage.blockSize * disk.blocks / 1024 / 1024 / 1024;
        const printSize = totalSize.toFixed(2);
        return (
          <Card.Grid>
            <Text strong>{disk.mountPoint}</Text><br/>
            <Text>Total Capacity: {printSize} GB</Text><br/>
            <Progress percent={disk.capacity}/>
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
        <Card>
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
      <Row><Col span={8}>
          <Uptime/>
        </Col></Row>
      <Row><VmStat/></Row>
      <Row><DiskUsage/></Row>
      <Row><SwapUsage/></Row>
    </div>
  );
}

export default Dashboard;
