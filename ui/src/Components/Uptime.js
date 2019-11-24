import React, { useState, useEffect } from 'react';
import { getJSON } from '../helpers.js';
import './Uptime.css';

const uptimeURL = "http://192.168.0.11:8001/api/uptime";
const updateTime = 5000;

function Uptime() {
  const [uptime, setUptime] = useState({loadAvg: []});

  useEffect(() => {
    getJSON(uptimeURL).then(res => setUptime(res));
    const interval = setInterval(() => {
      getJSON(uptimeURL).then(res => setUptime(res));
    }, updateTime);

    return () => {
      clearInterval(interval);
    };
  }, []);

  return (
    <div className="uptime">
      <div className="uptime-time">Time: {uptime.time}</div>
      <div className="uptime-uptime">Uptime: {uptime.uptime}</div>
      <div className="uptime-users">Users: {uptime.users}</div>
      <div className="uptime-loadavg">Load Average:
        {uptime.loadAvg.map((avg, idx) => (
          <div className="uptime-avg" key={idx}>{avg}</div>
        ))}
      </div>
    </div>
  );
}

export default Uptime;
