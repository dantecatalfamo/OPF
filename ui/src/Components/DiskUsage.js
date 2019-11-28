import React, { useState, useEffect } from 'react';
import { getJSON } from '../helpers.js';
import { serverURL } from '../config.js';
import './DiskUsage.css';

const diskUsageURL = `${serverURL}/api/disk-usage`;
const updateTime = 5000;


function DiskUsage (props) {
  const [diskUsage, setDiskUsage] = useState();

  useEffect(() => {
    getJSON(diskUsageURL).then(res => setDiskUsage(res));
    const interval = setInterval(() => {
      getJSON(diskUsageURL).then(res => setDiskUsage(res));
    }, updateTime);

    return () => {
      clearInterval(interval);
    };
  }, []);

  let diskUsageRows;


  if (diskUsage) {
    diskUsageRows = diskUsage.filesystems.map((fs, idx) => (
      <tr key={idx}>
        <td>{fs.filesystem}</td>
        <td>{fs.blocks}</td>
        <td>{fs.used}</td>
        <td>{fs.available}</td>
        <td>{fs.capacity}%</td>
        <td>{fs.mountPoint}</td>
      </tr>
    ));
  }

  return (
    <div className="diskusage">
      <table>
        <thead>
          <tr>
            <th>Filesystem</th>
            <th>Blocks</th>
            <th>Used</th>
            <th>Available</th>
            <th>Capacity</th>
            <th>Mount Point</th>
          </tr>
        </thead>
        <tbody>
          {diskUsageRows}
        </tbody>
      </table>
    </div>
  );
}

export default DiskUsage;
