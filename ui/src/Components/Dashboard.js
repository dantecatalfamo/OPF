import React, { useState, useEffect, useReducer } from 'react';
import { Card, Typography, Row, Col, Progress, Tooltip, Spin, Grid } from 'antd';
import { ResponsiveContainer, LineChart, Line, XAxis, YAxis, Legend, Tooltip as ChartTooltip, CartesianGrid } from 'recharts';
import { getJSON, useJSON, useJsonUpdates, timeSince, digestMessage, stringToColor } from '../helpers';
import { serverURL, prometheusURL } from '../config';
import './Dashboard.css';

const { Text, Title } = Typography;
const { useBreakpoint } = Grid;

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

function Uname(props) {
  const [uname, setUname] = useState();
  const [date, setDate] = useState();
  useJSON(unameURL, setUname);
  useJsonUpdates(dateURL, setDate, updateTime);

  return (
    <Card>
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
    <Card title="Uptime">
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
    <Card title="Load Average">
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
    <Card title="RAM">
      <div style={{textAlign: "center"}}>
        <Tooltip title={<div>{active} MB Active <br/>{other} MB Other<br/>{total} MB Total</div>}>
          <Progress percent={percentUsed} success={{percent: percentActive}} type="dashboard"/>
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
    <Card title="CPU">
      <div style={{textAlign: "center"}}>
        <Tooltip title={<div>User: {userPercent}% <br/> System: {systemPercent}%</div>}>
          <Progress percent={usagePercent} success={{percent: userPercent}} type="dashboard" />
        </Tooltip>
      </div>
    </Card>
  );
};

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
    <Card title="Swap Usage">
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

async function getInterfaceGraphData(query, label) {
  const endTime = new Date().getTime() / 1000;
  const range = 12 * 60 * 60;
  const startTime = endTime - range;
  const promQuery = prometheusURL + "query_range?" + new URLSearchParams({
    query: query,
    end: endTime,
    start: startTime,
    step: 120,
  });

  const res = await fetch(promQuery);
  const json = await res.json();

  const datas = {};
  json.data.result.forEach(series => {
    const name = series.metric[label];
    const values = series.values;
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
  }).sort((a, b) => -(a - b));
  return newChartData;
}

function InterfaceRx(props) {
  const { height } = props;
  const [chartLineColors, setChartLineColors] = useState({});
  const [keys, setKeys] = useState([]);
  const [data, setData] = useState([]);

  useEffect(() => {
    async function runJob() {
      const rxData = await getInterfaceGraphData('rate(node_network_receive_bytes_total[5m])', 'device');
      setData(rxData);
      const ifKeys = Object.keys(rxData[0]).filter(key => key != 'time' && !key.startsWith('lo'));
      setKeys(ifKeys);
    }
    runJob();
    const interval = setInterval(runJob, 30 * 1000);

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
    <Card title="Interface Received (KB/s)">
      <ResponsiveContainer height={height}>
        <LineChart data={data} syncId="networkInterface">
          <XAxis dataKey="time" minTickGap={30} />
          <YAxis/>
          <CartesianGrid strokeDasharray="3 4"/>
          <ChartTooltip formatter={(val, name, props) => (val.toFixed(4))} offset={50}/>
          <Legend/>
          {keys.map(key => (<Line dataKey={key} key={key} stroke={chartLineColors[key]} type="monotoneX" dot={false} />))}
        </LineChart>
      </ResponsiveContainer>
    </Card>
  );
}

function InterfaceTx(props) {
  const { height } = props;
  const [chartLineColors, setChartLineColors] = useState({});
  const [keys, setKeys] = useState([]);
  const [data, setData] = useState([]);

  useEffect(() => {
    async function runJob() {
      const txData = await getInterfaceGraphData('rate(node_network_transmit_bytes_total[5m])', 'device');
      setData(txData);
      const ifKeys = Object.keys(txData[0]).filter(key => key != 'time' && !key.startsWith('lo'));
      setKeys(ifKeys);
    }
    runJob();
    const interval = setInterval(runJob, 30 * 1000);

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
    <Card title="Interface Transmitted (KB/s)">
      <ResponsiveContainer height={height}>
        <LineChart data={data} syncId="networkInterface">
          <XAxis dataKey="time" minTickGap={30} />
          <YAxis/>n
          <CartesianGrid strokeDasharray="3 4"/>
          <ChartTooltip formatter={(val, name, props) => (val.toFixed(4))} offset={50}/>
          <Legend/>
          {keys.map(key => (<Line dataKey={key} key={key} stroke={chartLineColors[key]} type="monotoneX" dot={false} />))}
        </LineChart>
      </ResponsiveContainer>
    </Card>
  );
}

function Dashboard(props) {

  const breakpoint = useBreakpoint();
  const wideLayout = breakpoint.xxl;

  const graphs = (
    <Col span={24}  xxl={{span: 12}}>
      <Row gutter={[4, 4]}>
    <Col span={24}><InterfaceRx height={wideLayout ? 315 : 200}/></Col>
        <Col span={24}><InterfaceTx height={wideLayout ? 315 : 200}/></Col>
      </Row>
    </Col>
  );

  const diskUsage = (
    <>
      <Col span={24}><DiskUsage/></Col>
      <Col span={24}><SwapUsage/></Col>
    </>
  );

  return (
    <Col
      xxl={{ span: 18, offset: 3 }}
      lg={{  span: 14, offset: 5 }}
    >
      <Row gutter={[4, 4]}>
        <Col span={24}><Uname/></Col>

        <Col span={24} xxl={{span: 12}}>
          <Row gutter={[4, 4]}>
            <Col span={12}><Uptime/></Col>
            <Col span={12}><LoadAvg/></Col>
            <Col span={12}><Ram/></Col>
            <Col span={12}><CpuUsage/></Col>
            {wideLayout ? diskUsage : null}
          </Row>
        </Col>

        {graphs}

        {wideLayout ? null : diskUsage}

      </Row>
    </Col>
  );
}

export default Dashboard;
