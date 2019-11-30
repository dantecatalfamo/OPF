import React, { useState, useEffect } from 'react';
import { getJSON } from '../helpers.js';
import { serverURL } from '../config.js';
import './Process.css';


const processURL = `${serverURL}/api/processes`;
const updateTime = 3000;

function Processes() {
  const [processes, setProcesses] = useState([]);

  useEffect(() => {
    getJSON(processURL).then(res => setProcesses(res));
    const interval = setInterval(() => {
      getJSON(processURL).then(res => setProcesses(res));
    }, updateTime);

    return () => {
      clearInterval(interval);
    };
  }, []);

  return (
    <div className="processes">
      <table>
        <thead>
          <tr>
            <th>User</th>
            <th>Group</th>
            <th>PID</th>
            <th>PPID</th>
            <th>Stat</th>
            <th>%CPU</th>
            <th>%MEM</th>
            <th>VSZ</th>
            <th>RSS</th>
            <th>Nice</th>
            <th>Pri</th>
            <th>WChan</th>
            <th>Started</th>
            <th>Time</th>
            <th>Term</th>
            <th>Command</th>
          </tr>
        </thead>
        <tbody>
        {processes.map(proc => {
          return (
            <tr key={proc.pid}>
              <td>{proc.user}</td>
              <td>{proc.group}</td>
              <td>{proc.pid}</td>
              <td>{proc.parentPid}</td>
              <td>{proc.stat.join(", ")}</td>
              <td>{proc.percentCPU}</td>
              <td>{proc.percentMemory}</td>
              <td>{proc.virtualMemorySize}</td>
              <td>{proc.residentSetSize}</td>
              <td>{proc.nice}</td>
              <td>{proc.priority}</td>
              <td>{proc.waitChannel}</td>
              <td>{proc.started}</td>
              <td>{proc.time}</td>
              <td>{proc.terminal}</td>
              <td>{proc.command}</td>
            </tr>
          );
        })}
        </tbody>
      </table>
    </div>
  );
}

export default Processes;
