import React, { useState, useEffect } from 'react';
import { getJSON } from '../helpers.js';
import './RC.css';

const rcAllURL = "http://192.168.0.11:8001/api/rc-all";
const rcOnURL = "http://192.168.0.11:8001/api/rc-on";
const rcStartedURL = "http://192.168.0.11:8001/api/rc-started";

function RC() {
  const [rcAll, setRcAll] = useState([]);
  const [rcOn, setRcOn] = useState(null);
  const [rcStarted, setRcStarted] = useState(null);

  useEffect(() => {
    getJSON(rcAllURL).then(res => setRcAll(res));
    getJSON(rcOnURL).then(res => setRcOn(res));
    getJSON(rcStartedURL).then(res => setRcStarted(res));
  }, []);

  return (
    <div className="rc">
      <table>
        <thead>
          <tr>
            <th>Service</th>
            <th>Enabled</th>
            <th>Started</th>
          </tr>
        </thead>
        <tbody>
          {rcAll.map(rc => {
            let on = "...";
            let started = "...";
            if (rcOn) {
              on = rcOn.includes(rc) ? "[X]" : "[ ]";
            }
            if (rcStarted) {
              started = rcStarted.includes(rc) ? "[X]" : "[ ]";
            }
            return (
              <tr key={rc}>
                <td>{rc}</td>
                <td>{on}</td>
                <td>{started}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export default RC;
