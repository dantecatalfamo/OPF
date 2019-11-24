import React, { useState, useEffect } from 'react';
import './NetstatInterfaces.css';

async function getStates() {
  const url = "http://192.168.0.11:8001/api/netstat-interfaces";
  const response = await fetch(url);
  return await response.json();
}

function NetstatInterfaces() {
  const [states, setStates] = useState([]);

  useEffect(() => {
    getStates().then(res => {
      setStates(res);
    });
    const interval = setInterval(() => {
      getStates().then(res => {
        setStates(res);
      });
    }, 2000);

    return () => {
      clearInterval(interval);
    };
  }, []);

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
          {states.map((iface, idx) => (
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
