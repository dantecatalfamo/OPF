import React, { useState } from 'react';
import { useJsonUpdates } from '../helpers.ts';
import { serverURL } from '../config.ts';
import './Hardware.css';

const hardwareURL = `${serverURL}/api/hardware`;
const updateTime = 5000;

function Hardware() {
  const [hardware, setHardware] = useState();

  useJsonUpdates(hardwareURL, setHardware, updateTime);

  if (!hardware) {
    return '';
  }

  const sensors = hardware.sensors.map((sensor) => (
    <tr key={sensor.path.toString()}>
      <th>Sensor &gt;</th>
      <td>{`${sensor.path.join(' > ')}: ${sensor.value}`}</td>
    </tr>
  ));

  const disks = hardware.disks.map((disk) => (
    <tr key={disk.name}>
      <th>Disk &gt;</th>
      <td>
        {disk.name}
        {' '}
        [
        {disk.duid}
        ]
      </td>
    </tr>
  ));

  return (
    <div className="hardware">
      <table>
        <tbody>
          <tr>
            <th>Machine</th>
            <td>{hardware.machine}</td>
          </tr>
          <tr>
            <th>Model</th>
            <td>{hardware.model}</td>
          </tr>
          <tr>
            <th>Byte Order</th>
            <td>{hardware.byteOrder}</td>
          </tr>
          <tr>
            <th>Page Size</th>
            <td>{hardware.pageSize}</td>
          </tr>
          <tr>
            <th>Disk Count</th>
            <td>{hardware.diskCount}</td>
          </tr>
          {disks}
          {sensors}
          <tr>
            <th>Number CPU</th>
            <td>{hardware.ncpu}</td>
          </tr>
          <tr>
            <th>CPU Speed</th>
            <td>{hardware.cpuSpeed}</td>
          </tr>
          <tr>
            <th>Vendor</th>
            <td>{hardware.vendor}</td>
          </tr>
          <tr>
            <th>Product</th>
            <td>{hardware.product}</td>
          </tr>
          <tr>
            <th>Version</th>
            <td>{hardware.version}</td>
          </tr>
          <tr>
            <th>Serial Number</th>
            <td>{hardware.serialNumber}</td>
          </tr>
          <tr>
            <th>UUID</th>
            <td>{hardware.uuid}</td>
          </tr>
          <tr>
            <th>Physical Memory</th>
            <td>{hardware.physMem}</td>
          </tr>
          <tr>
            <th>User Memory</th>
            <td>{hardware.userMem}</td>
          </tr>
          <tr>
            <th>Allow Power Down</th>
            <td>{hardware.allowPowerDown === 1 ? 'Yes' : 'No'}</td>
          </tr>
          <tr>
            <th>SMT</th>
            <td>{hardware.smt === 1 ? 'Enabled' : 'Disabled'}</td>
          </tr>
          <tr>
            <th>Number CPU Found</th>
            <td>{hardware.ncpuFound}</td>
          </tr>
          <tr>
            <th>Number CPU Online</th>
            <td>{hardware.ncpuOnline}</td>
          </tr>
        </tbody>
      </table>
    </div>
  );
}

export default Hardware;
