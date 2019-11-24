import React, { useState, useEffect } from 'react';
import './PfInterfaces.css';

async function getStates() {
  const url = "http://192.168.0.11:8001/api/pf-interfaces";
  const response = await fetch(url);
  return await response.json();
}

function PfStates() {
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
    <div className="pfinterfaces">
      <table>
        <thead>
          <tr>
            <th>Interface</th>
            <th>Cleared</th>
            <th>References (States/Rules)</th>
            <th>In Pass (IPv4)</th>
            <th>In Block (IPv4)</th>
            <th>Out Pass (IPv4)</th>
            <th>Out Block (IPv4)</th>
            <th>In Pass (IPv6)</th>
            <th>In Block (IPv6)</th>
            <th>Out Pass (IPv6)</th>
            <th>Out Block (IPv6)</th>
          </tr>
        </thead>
        <tbody>
          {states.map(iface => (
            <tr key={iface.interface}>
              <td className="left">{iface.interface}</td>
              <td className="left">{iface.cleared}</td>
              <td>{`${iface.references.states}/${iface.references.rules}`}</td>
              <td>{`${iface.in4pass.packets}/${iface.in4pass.bytes}`}</td>
              <td>{`${iface.in4block.packets}/${iface.in4block.bytes}`}</td>
              <td>{`${iface.out4pass.packets}/${iface.out4pass.bytes}`}</td>
              <td>{`${iface.out4block.packets}/${iface.out4block.bytes}`}</td>
              <td>{`${iface.in6pass.packets}/${iface.in6pass.bytes}`}</td>
              <td>{`${iface.in6block.packets}/${iface.in6block.bytes}`}</td>
              <td>{`${iface.out6pass.packets}/${iface.out6pass.bytes}`}</td>
              <td>{`${iface.out6block.packets}/${iface.out6block.bytes}`}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default PfStates;
