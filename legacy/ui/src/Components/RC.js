import React, { useState, useEffect } from 'react';
import {
  List, Badge, Col, Card,
} from 'antd';
import { getJSON } from '../helpers.ts';
import { serverURL } from '../config.ts';
import RcFlags from './RcFlags';
import RcEnabled from './RcEnabled';
import RcStarted from './RcStarted';
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
    getJSON(rcAllURL).then((res) => setRcAll(res));
    getJSON(rcOnURL).then((res) => setRcOn(res));
    getJSON(rcStartedURL).then((res) => setRcStarted(res));
  }, []);

  const handleServiceStarted = (service, started) => {
    if (started && !rcStarted.includes(service)) {
      setRcStarted([...rcStarted, service]);
    } else {
      setRcStarted(rcStarted.filter((s) => s !== service));
    }
  };

  const handleServiceEnabled = (service, enabled) => {
    if (enabled && !rcOn.includes(service)) {
      setRcOn([...rcOn, service]);
    } else {
      setRcOn(rcOn.filter((s) => s !== service));
    }
  };

  return (
    <Col
      xxl={{ span: 10, offset: 7 }}
      xl={{ span: 12, offset: 6 }}
      lg={{ span: 14, offset: 5 }}
    >
      <Card>
        <List
          loading={!rcAll}
          itemLayout="horizontal"
          bordered
          dataSource={rcAll}
          renderItem={(item) => {
            let badge;
            let started;
            const special = rcSpecials.includes(item);
            if (!rcStarted) {
              badge = 'processing';
              started = null;
            } else if (rcSpecials.includes(item)) {
              badge = 'default';
            } else if (rcStarted.includes(item)) {
              badge = 'green';
              started = true;
            } else {
              badge = 'red';
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
              <RcStarted
                loading={started == null}
                started={started}
                enabled={enabled}
                service={item}
                onStarted={handleServiceStarted}
              />
            );

            const enableSwitch = (
              <RcEnabled
                loading={enabled === null}
                enabled={enabled}
                service={item}
                onEnabled={handleServiceEnabled}
              >
                {enabled ? 'Disable' : 'Enable'}
              </RcEnabled>
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
                ]}
              >
                <List.Item.Meta
                  title={(
                    <span>
                      <Badge status={badge} />
                      {' '}
                      {item}
                    </span>
)}
                />
              </List.Item>
            );
          }}
        />
      </Card>
    </Col>
  );
}

export default RC;
