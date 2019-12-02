import React, { useState, useEffect } from 'react';
import { List, Button, Badge, Switch } from 'antd';
import { getJSON } from '../helpers.js';
import { serverURL } from '../config.js';
import './RC.css';

const rcAllURL = `${serverURL}/api/rc-all`;
const rcOnURL = `${serverURL}/api/rc-on`;
const rcStartedURL = `${serverURL}/api/rc-started`;

const rcSpecials = ['pf', 'check_quotas', 'ipsec', 'accounting'];

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
    <List
      itemLayout="horizontal"
      dataSource={rcAll}
      renderItem={item => {
        let badge;
        let started;
        const special = rcSpecials.includes(item);
        if (!rcStarted) {
          badge = "processing";
          started = null;
        } else if (rcSpecials.includes(item)) {
          badge = "default";
        } else if (rcStarted.includes(item)) {
          badge = "green";
          started = true;
        } else {
          badge = "red";
          started = false;
        }
        let enabled;
        if (!rcOn) {
          enabled = null;
        } else if (rcOn.includes(item)) {
          enabled = true;
        } else {
          enabled = false;
        }

        const flagsButton = (
          <Button loading={!rcOn}>Flags</Button>
        );

        const startButton = (
          <Button
            loading={started == null}
            type={started === true ? "danger" : "primary"}
          >{started ? "Stop" : "Start"}</Button>
        );

        const enableSwitch = (
          <Switch
            loading={enabled === null}
            checked={enabled}
          >{enabled ? "Disable" : "Enable"}</Switch>
        );

        return (
          <List.Item
            actions={[
              special ? null : startButton,
              enableSwitch,
              flagsButton,
            ]}>
            <List.Item.Meta
              title={<span><Badge status={badge} /> {item}</span>}
            />
          </List.Item>
               );}}
    />

  );

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
