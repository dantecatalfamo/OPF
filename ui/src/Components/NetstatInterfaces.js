import React, { useState, useEffect } from 'react';
import { getJSON, useJsonUpdates } from '../helpers.ts';
import { serverURL } from '../config.ts';
import './NetstatInterfaces.css';

const nsInterfacesURL = `${serverURL}/api/netstat-interfaces`;
const updateTime = 2000;

function NetstatInterfaces() {
  const [interfaces, setInterfaces] = useState([]);

  useJsonUpdates(nsInterfacesURL, setInterfaces, updateTime);

  return (
    <div className="netstatinterfaces">
      <table>
        <thead>
          <tr>
            <th>Interface</th>
            <th>MTU</th>
            <th>Network</th>
            <th>Address</th>
            <th>In Packets</th>
            <th>In Fail</th>
            <th>Out Packets</th>
            <th>Out Fail</th>
            <th>Colls</th>
          </tr>
        </thead>
        <tbody>
          {interfaces.map((iface, idx) => (
            <tr key={idx}>
              <td>{iface.name}</td>
              <td>{iface.mtu}</td>
              <td>{iface.network}</td>
              <td>{iface.address}</td>
              <td>{iface.inPackets}</td>
              <td>{iface.inFail}</td>
              <td>{iface.outPackets}</td>
              <td>{iface.outFail}</td>
              <td>{iface.colls}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default NetstatInterfaces;
