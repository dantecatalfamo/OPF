import React, { useState, useEffect } from 'react';
import { getJSON } from '../helpers.js';
import { serverURL } from '../config.js';
import './PfStates.css';

const pfStatesURL = `${serverURL}/api/pf-states`;
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
          {states.map(state => {
            let bg = "none";
            let fg = "black";
            let style = {};
            let rule;
            if (state.proto.includes("tcp")) {
              bg = "#d5f3fd";
            }
            if (state.proto.includes("udp")) {
              bg = "#ffecec";
            }
            if (state.rule === -1) {
              rule = "*";
            } else {
              rule = state.rule;
            }
            if ((state.sourceState + state.destinationState).includes("NO_TRAFFIC")) {
              fg = "grey";
            }
            style.backgroundColor = bg;
            style.color = fg;
            return (
              <tr style={style} key={state.id}>
              <td>{state.proto}</td>
              <td>{state.direction}</td>
              <td>{`${state.sourceIP}:${state.sourcePort}`}</td>
              <td>{`${state.destinationIP}:${state.destinationPort}`}</td>
              <td>{`${state.sourceState}:${state.destinationState}`}</td>
              <td>{state.age}</td>
              <td>{state.expires}</td>
              <td>{`${state.packetsSent}:${state.packetsReceived}`}</td>
              <td>{`${state.bytesSent}:${state.bytesReceived}`}</td>
              <td>{rule}</td>
              <td>{state.gateway}</td>
            </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export default PfStates;
