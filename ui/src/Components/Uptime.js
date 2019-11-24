import React, { useState, useEffect } from 'react';
import './Uptime.css';

async function getUptime() {
  const url = "http://192.168.0.11:8001/api/uptime";
  const response = await fetch(url);
  return await response.json();
}

function Uptime() {
  const [uptime, setUptime] = useState({loadAvg: []});

  useEffect(() => {
    getUptime().then(res => {
      setUptime(res);
    });
    const interval = setInterval(() => {
      getUptime().then(res => {
        setUptime(res);
      });
    }, 5000);

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
