import React, { useState, useEffect } from 'react';
import { List, Button, Badge, Switch, Col, Card } from 'antd';
import { getJSON } from '../helpers.js';
import { serverURL } from '../config.js';
import RcFlags from './RcFlags';
import './RC.css';

const rcAllURL = `${serverURL}/api/rc-all`;
const rcOnURL = `${serverURL}/api/rc-on`;
const rcStartedURL = `${serverURL}/api/rc-started`;

const rcSpecials = ['pf', 'check_quotas', 'ipsec', 'accounting', 'library_aslr'];

function RC() {
  const [rcAll, setRcAll] = useState();
  const [rcOn, setRcOn] = useState(null);
  const [rcStarted, setRcStarted] = useState(null);

  useEffect(() => {
    getJSON(rcAllURL).then(res => setRcAll(res));
    getJSON(rcOnURL).then(res => setRcOn(res));
    getJSON(rcStartedURL).then(res => setRcStarted(res));
  }, []);

  return (
    <Col
      xxl={{ span: 8,  offset: 8 }}
      xl={{  span: 10, offset: 7 }}
      lg={{  span: 12, offset: 6 }}
    >
      <Card>
        <List
          loading={!rcAll}
          itemLayout="horizontal"
          bordered
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

            const flagsButton = (
              <RcFlags
                disabled={special || !enabled}
                loading={!rcOn}
                service={item}
              />
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
      </Card>
    </Col>
  );
}

export default RC;
