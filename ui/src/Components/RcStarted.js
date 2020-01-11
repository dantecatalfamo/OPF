import React, { useState, useEffect } from 'react';
import { Button, notification } from 'antd';
import { postJSON } from '../helpers.js';
import { serverURL } from '../config.js';

function RcStarted(props) {
  const loadingInit = props.loading;
  const started = props.started;
  const onStarted = props.onStarted;
  const service = props.service;
  const serviceURL = `${serverURL}/api/rc/${service}/started`;
  const [loadingSelf, setLoadingSelf] = useState(null);
  const loading = loadingSelf === null ? loadingInit : loadingSelf;

  const handleClick = () => {
    console.log(`POST ${serviceURL} with ${!started}`);
    setLoadingSelf(true);
    postJSON(serviceURL, !started)
      .then((res) => {
        onStarted(service, res);
        setLoadingSelf(false);
      }).catch((res) => {
        notification['error']({
          message: "Error",
          description: `Failed to start ${service}. Check logs for details.`,
        });
        setLoadingSelf(false);
      });
  };

  return (
    <Button
      loading={loading}
      type={started ? "danger" : "primary"}
      onClick={handleClick}
    >
      {started ? "Stop" : "Start"}
    </Button>
  );
}

export default RcStarted;
