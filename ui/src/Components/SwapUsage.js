import React, { useState, useEffect } from 'react';
import { getJSON, useJsonUpdates } from '../helpers.js';
import { serverURL } from '../config.js';
import './SwapUsage.css';

const swapUsageURL = `${serverURL}/api/swap-usage`;
const updateTime = 5000;

function SwapUsage() {
  const [swapUsage, setSwapUsage] = useState();

  useJsonUpdates(swapUsageURL, setSwapUsage, updateTime);

  if (!swapUsage) {
    return "";
  }

  let swapDevices = swapUsage.devices.map(device => (
    <tr key={device.device}>
      <td>{device.device}</td>
      <td>{device.blocks}</td>
      <td>{device.used}</td>
      <td>{device.available}</td>
      <td>{device.capacity}%</td>
      <td>{device.priority}</td>
    </tr>
  ));

  return (
    <div className="swapusage">
      <table>
        <thead>
          <tr>
            <th>Device</th>
            <th>Blocks</th>
            <th>Used</th>
            <th>Available</th>
            <th>Capacity</th>
            <th>Priority</th>
          </tr>
        </thead>
        <tbody>
          {swapDevices}
        </tbody>
      </table>
    </div>
  );
}

export default SwapUsage;
