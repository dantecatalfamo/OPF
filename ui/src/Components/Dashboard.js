import React, { useState, useEffect, useReducer } from 'react';
import { Card, Typography, Row, Col, Progress, Tooltip, Spin } from 'antd';
import { ResponsiveContainer, LineChart, Line, XAxis, YAxis, Legend, Tooltip as ChartTooltip } from 'recharts';
import { getJSON, useJSON, useJsonUpdates, timeSince, digestMessage, stringToColor } from '../helpers';
import { serverURL, prometheusURL } from '../config';
import './Dashboard.css';

const { Text, Title } = Typography;

const unameURL = `${serverURL}/api/uname`;
const loadavgURL = `${serverURL}/api/loadavg`;
const hardwareURL = `${serverURL}/api/hardware`;
const bootTimeURL = `${serverURL}/api/boot-time`;
const dateURL = `${serverURL}/api/date`;
const uptimeURL = `${serverURL}/api/uptime`;
const ramURL = `${serverURL}/api/ram`;
const vmstatURL = `${serverURL}/api/vmstat`;
const diskUsageURL = `${serverURL}/api/disk-usage`;
const swapUsageURL = `${serverURL}/api/swap-usage`;
const cpuStatesURL = `${serverURL}/api/cpu-states`;
const updateTime = 5000;
const longUpdateTime = 20000;

const cardStyle = {
  style: {margin: 2}
};

function Uname(props) {
  const [uname, setUname] = useState();
  const [date, setDate] = useState();
  useJSON(unameURL, setUname);
  useJsonUpdates(dateURL, setDate, updateTime);

  return (
    <Card {...cardStyle}>
      <Title>{uname ? uname.nodeName : ""}</Title>
      <Row>
        <Col span={12}>
          <Text>{uname ? `${uname.osName} ${uname.osRelease} (${uname.hardware})` : ""}</Text>
        </Col>
        <Col span={12} style={{textAlign: "right"}}>
          <Text>{date ? date : ""}</Text>
        </Col>
      </Row>
    </Card>
  );
}

function Uptime(props) {
  const [bootTime, setBootTime] = useState();
  const [, setTick] = useState(0);
  useJsonUpdates(bootTimeURL, setBootTime, longUpdateTime);

  const time = timeSince(new Date(bootTime));
  useEffect(() => {
    const interval = setInterval(() => setTick(t => t + 1), updateTime);
    return () => clearInterval(interval);
  }, []);

  let days = "";
  let hours = "";
  let minutes = "";

  if (time.days) {
    days = <span>{time.days} <span className="dashboard-days"> Days </span></span>;
  }

  if (time.hours) {
    hours = <span>{time.hours} <span className="dashboard-days"> Hours </span></span>;
  }

  if (time.minutes) {
    minutes = <span>{time.minutes} <span className="dashboard-days"> Minutes </span></span>;
  }

  const seconds = <span>{time.seconds} <span className="dashboard-days"> Seconds </span></span>;

  return (
    <Card title="Uptime" {...cardStyle}>
      <div style={{textAlign: "center"}}>
        <Tooltip title={bootTime}>
          <Text>
            {days}
            {hours}
            {minutes}
            {seconds}
          </Text>
        </Tooltip>
      </div>
    </Card>
  );
}

function loadAvgWarn(loadAvg, ncpu) {
  const low = 0.75;
  const medium = 1;
  const ratio = loadAvg / ncpu;
  if (ratio < low) {
    return "";
  } else if (ratio < medium) {
    return "warning";
  } else {
    return "danger";
  }
}

function LoadAvg(props) {
  const [loadAvg, setLoadAvg] = useState();
  const [hardware, setHardware] = useState();
  useJsonUpdates(loadavgURL, setLoadAvg, updateTime);
  useJSON(hardwareURL, setHardware);

  const colProps = {
    span: 8,
    style: {textAlign: "center"},
  };

  const warn1 = (loadAvg && hardware) ? loadAvgWarn(loadAvg[0], hardware.ncpuOnline) : "";
  const warn5 = (loadAvg && hardware) ? loadAvgWarn(loadAvg[1], hardware.ncpuOnline) : "";
  const warn15 = (loadAvg && hardware) ? loadAvgWarn(loadAvg[2], hardware.ncpuOnline) : "";

  return (
    <Card title="Load Average" {...cardStyle}>
      <Row>
        <Col {...colProps}>
          <Tooltip title="1 Minute">
            <Text type={warn1} strong>{loadAvg ? loadAvg[0] : "0.00"}</Text>
          </Tooltip>
        </Col>
        <Col {...colProps}>
          <Tooltip title="5 Minutes">
            <Text type={warn5} strong>{loadAvg ? loadAvg[1] : "0.00"}</Text>
          </Tooltip>
        </Col>
        <Col {...colProps}>
          <Tooltip title="15 Minutes">
            <Text type={warn15} strong>{loadAvg ? loadAvg[2] : "0.00"}</Text>
          </Tooltip>
        </Col>
      </Row>
    </Card>
  );
}

function Ram(props) {
  const [ram, setRam] = useState({});
  useJsonUpdates(ramURL, setRam, updateTime);

  const total = ram.total;
  const active = ram.active;
  const free = ram.free;
  const other = ram.total - (ram.free + ram.active);
  const percentUsed = Number(((total - free) / total * 100).toFixed(2));
  const percentActive = Number((active / total * 100).toFixed(2));

  return (
    <Card title="RAM" {...cardStyle}>
      <div style={{textAlign: "center"}}>
        <Tooltip title={<div>{active} MB Active <br/>{other} MB Other<br/>{total} MB Total</div>}>
          <Progress percent={percentUsed} successPercent={percentActive} type="dashboard"/>
        </Tooltip>
      </div>
    </Card>
  );
}

function CpuUsage(props) {
  const [cpuStates, updateCpuStates] = useReducer((state, newState) => ({
    old: state.new,
    new: newState,
  }), {old: {}, new: {user: 0, nice: 0, sys: 0, spin: 0, interrupt: 0, idle: 0}});

  useJsonUpdates(cpuStatesURL, updateCpuStates, updateTime);

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
    <Card title="CPU" {...cardStyle}>
      <div style={{textAlign: "center"}}>
        <Tooltip title={<div>User: {userPercent}% <br/> System: {systemPercent}%</div>}>
          <Progress percent={usagePercent} successPercent={userPercent} type="dashboard" />
        </Tooltip>
      </div>
    </Card>
  );
};

function DiskUsage(props) {
  const [diskUsage, setDiskUsage] = useState();
  useJsonUpdates(diskUsageURL, setDiskUsage, updateTime);

  return (
    <Card title="Disk Usage" {...cardStyle}>
      {diskUsage ? diskUsage.filesystems.map(disk => {
        const used = Number((diskUsage.blockSize * disk.used / 1024 / 1024 / 1024).toFixed(2));
        const totalSize = Number((diskUsage.blockSize * disk.blocks / 1024 / 1024 / 1024).toFixed(2));
        return (
          <Card.Grid key={disk.mountPoint}>
            <Tooltip title={<span>{disk.filesystem}</span>}>
              <Text strong>{disk.mountPoint}</Text>
            </Tooltip>
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
    <Card title="Swap Usage" {...cardStyle}>
      {swapUsage ? swapUsage.devices.map(device => {
        const used = Number((swapUsage.blockSize * device.used / 1024 / 1024 / 1024).toFixed(2));
        const totalSize = Number((swapUsage.blockSize * device.blocks / 1024 / 1024 / 1024).toFixed(2));
        return (
          <Card.Grid key={device.device}>
            <Tooltip title={<span>Priority: {device.priority}</span>}>
              <Text strong>{device.device}</Text>
            </Tooltip>
            <Tooltip title={<span>{used} GB / {totalSize} GB</span>}>
              <Progress percent={device.capacity}/>
            </Tooltip>
          </Card.Grid>
        );
      }) : ""}
    </Card>
  );
}

async function getInterfaceGraphData() {
  const endTime = new Date().getTime() / 1000;
  const range = 12 * 60 * 60;
  const startTime = endTime - range;
  const promQuery = prometheusURL + "query_range?" + new URLSearchParams({
    query: 'rate(node_network_receive_bytes_total[2m])',
    end: endTime,
    start: startTime,
    step: 120,
  });

  const res = await fetch(promQuery);
  const json = await res.json();

  const datas = {};
  json.data.result.forEach(iface => {
    const name = iface.metric.device;
    const values = iface.values;
    values.forEach(value => {
      datas[value[0]] ||= {};
      datas[value[0]][name] = value[1] / 1024;
    });
  });
  const dataArray = [];
  const newChartData = Object.entries(datas).map(entry => {
    const [key, val] = entry;
    val['time'] = new Date(Number(key) * 1000).toLocaleTimeString();
    return val;
  });
  return newChartData;
}

function InterfaceGraph(props) {
  const [chartLineColors, setChartLineColors] = useState({});
  const [keys, setKeys] = useState([]);
  const [data, setData] = useState([]);

  useEffect(() => {
    getInterfaceGraphData().then(ifData => {
      setData(ifData);
      const ifKeys = Object.keys(ifData[0]).filter(key => key != 'time' && !key.startsWith('lo'));
      setKeys(ifKeys);
    });
    const interval = setInterval(async () => {
      const ifData = await getInterfaceGraphData();
      const filteredKeys = Object.keys(ifData[0]).filter(key => key != 'time' && !key.startsWith('lo'));
      setData(ifData);
      setKeys(filteredKeys);
    }, 30 * 1000);

    return () => clearInterval(interval);
  }, []);

  useEffect(async () => {
    const colorMap = {};
    for await (const key of keys) {
      const color = await stringToColor(key);
      colorMap[key] = color;
    }
    setChartLineColors(colorMap);
  }, [keys]);

  return (
    <Card title="Network Usage (KB/s)" {...cardStyle}>
      <ResponsiveContainer height={250}>
        <LineChart data={data}>
          <XAxis dataKey="time" />
          <YAxis/>
          <ChartTooltip/>
          <Legend/>
          {keys.map(key => (<Line dataKey={key} stroke={chartLineColors[key]} type="monotoneX" dot={false} />))}
        </LineChart>
      </ResponsiveContainer>
    </Card>
  );
}

function Dashboard(props) {
  return (
    <Col
      xxl={{ span: 10, offset: 7 }}
      xl={{  span: 12, offset: 6 }}
      lg={{  span: 14, offset: 5 }}
    >
      <Row>
        <Col span={24}><Uname/></Col>
      </Row>
      <Row>
        <Col span={12}><Uptime/></Col>
        <Col span={12}><LoadAvg/></Col>
      </Row>
      <Row>
        <Col span={12}><Ram/></Col>
        <Col span={12}><CpuUsage/></Col>
      </Row>
      <Row>
        <Col span={24}><InterfaceGraph/></Col>
      </Row>
      <Row>
        <Col span={24}><DiskUsage/></Col>
      </Row>
      <Row>
        <Col span={24}><SwapUsage/></Col>
      </Row>
    </Col>
  );
}

export default Dashboard;
