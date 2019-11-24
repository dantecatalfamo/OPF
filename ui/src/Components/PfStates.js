import React, { useState, useEffect } from 'react';
import { getJSON } from '../helpers.js';
import './PfStates.css';

const pfStatesURL = "http://192.168.0.11:8001/api/pf-states";
const updateTime = 2000;

function PfStates() {
  const [states, setStates] = useState([]);

  useEffect(() => {
    getJSON(pfStatesURL).then(res => setStates(res));
    const interval = setInterval(() => {
      getJSON(pfStatesURL).then(res => setStates(res));
    }, updateTime);

    return () => {
      clearInterval(interval);
    };
  }, []);

  return (
    <div className="pfstates">
      <table>
        <thead>
          <tr>
            <th className="proto">Proto</th>
            <th>Direction</th>
            <th className="ip">Source</th>
            <th className="ip">Destination</th>
            <th>State</th>
            <th>Age</th>
            <th>Expires</th>
            <th>Packets</th>
            <th>Bytes</th>
            <th>Rule</th>
            <th>Gateway</th>
          </tr>
        </thead>
        <tbody>
          {states.map(state => (
            <tr key={state.id}>
              <td>{state.proto}</td>
              <td>{state.direction}</td>
              <td>{`${state.sourceIP}:${state.sourcePort}`}</td>
              <td>{`${state.destinationIP}:${state.destinationPort}`}</td>
              <td>{state.state}</td>
              <td>{state.age}</td>
              <td>{state.expires}</td>
              <td>{`${state.packetsSent}:${state.packetsReceived}`}</td>
              <td>{`${state.bytesSent}:${state.bytesReceived}`}</td>
              <td>{state.rule}</td>
              <td>{state.gateway}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default PfStates;
