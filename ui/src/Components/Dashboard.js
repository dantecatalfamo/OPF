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
    <>
      <Card style={{display: "inline-block", margin: 12}}>
        <p>Procs Running: {vmstat ? vmstat.procs.running : ""}</p>
        <p>Procs Sleeping: {vmstat ? vmstat.procs.sleeping : ""}</p>
        <p>Memory Active: {vmstat ? vmstat.memory.active : ""}</p>
        <p>Memory Free: {vmstat ? vmstat.memory.free : ""}</p>
      </Card>
      <Card style={{display: "inline-block", margin: 12}}>
        <p>Page Faults: {vmstat ? vmstat.page.faults : ""}</p>
        <p>Page Reclaims: {vmstat ? vmstat.page.reclaims : ""}</p>
        <p>Pages Paged In: {vmstat ? vmstat.page.pagedIn : ""}</p>
        <p>Pages Paged Out: {vmstat ? vmstat.page.pagedOut : ""}</p>
        <p>Pages Freed: {vmstat ? vmstat.page.freed : ""}</p>
        <p>Page Scanned: {vmstat ? vmstat.page.scanned : ""}</p>
      </Card>
      <Card style={{display: "inline-block", margin: 12}}>
        {vmstat ? vmstat.disks.map(disk => (
          <>
          <p>Name: {disk.name}</p>
            <p>Pages /s: {disk.transfers}</p>
          </>
        )) : ""}
      </Card>
      <Card style={{display: "inline-block", margin: 12}}>
        <p>Interrupts: {vmstat ? vmstat.traps.interrupts : ""}</p>
        <p>System Calls: {vmstat ? vmstat.traps.systemCalls : ""}</p>
        <p>Context Switches: {vmstat ? vmstat.traps.contextSwitch : ""}</p>
      </Card>
      <Card style={{display: "inline-block", margin: 12}}>
        <p>User: {vmstat ? vmstat.cpu.user : ""}</p>
        <p>System: {vmstat ? vmstat.cpu.system : ""}</p>
        <p>Idle: {vmstat ? vmstat.cpu.idle : ""}</p>
      </Card>
     </>
  );
}

function DiskUsage(props) {
  const [diskUsage, setDiskUsage] = useState();
  useJsonUpdates(diskUsageURL, setDiskUsage, updateTime);

  return (
    <>
      {diskUsage ? diskUsage.filesystems.map(disk => (
        <Card style={{display: "inline-block", margin: 12}}>
          <p>Filesystem: {disk.filesystem}</p>
          <p>Blocks: {disk.blocks}</p>
          <p>Used: {disk.used}</p>
          <p>Available: {disk.available}</p>
          <p>Capacity: {disk.capacity}%</p>
          <p>MountPoint: {disk.mountPoint}</p>
        </Card>
      )) : ""}
    </>
  );
}

function Dashboard(props) {
  return (
    <div>
      <Uname/>
      <Uptime/>
      <VmStat/>
      <DiskUsage/>
    </div>
  );
}

export default Dashboard;
