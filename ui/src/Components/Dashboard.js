import React, { useState, useEffect } from 'react';
import { Card } from 'antd';
import { getJSON, useJsonUpdates } from '../helpers';
import { serverURL } from '../config';

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
    <Card title={uname ? uname.nodeName : ""} style={{display: "inline-block", margin: 12}}>
      <p>OS Name: {uname ? `${uname.osName} ${uname.osRelease} (${uname.hardware})` : ""}</p>
    </Card>
  );
}

function Uptime(props) {
  const [uptime, setUptime] = useState();
  useJsonUpdates(uptimeURL, setUptime, updateTime);

  return (
    <Card style={{display: "inline-block", margin: 12}}>
      <p>Time: {uptime ? uptime.time : ""}</p>
      <p>Uptime: {uptime ? uptime.uptime : ""}</p>
      <p>Users: {uptime ? uptime.users : ""}</p>
      <p>Load Avg.: {uptime ? uptime.loadAvg.join(", ") : ""}</p>
    </Card>
  );
}

function VmStat(props) {
  const [vmstat, setVmstat] = useState();
  useJsonUpdates(vmstatURL, setVmstat, updateTime);

  return (
      <Card style={{display: "inline-block", margin: 12}}>
        <p>Procs Running: {vmstat ? vmstat.procs.running : ""}</p>
        <p>Procs Sleeping: {vmstat ? vmstat.procs.sleeping : ""}</p>
        <p>Memory Active: {vmstat ? vmstat.memory.active : ""}</p>
        <p>Memory Free: {vmstat ? vmstat.memory.free : ""}</p>

      </Card>
  );
}

function Dashboard(props) {
  return (
    <div>
      <Uname/>
      <Uptime/>
      <VmStat/>
    </div>
  );
}

export default Dashboard;
