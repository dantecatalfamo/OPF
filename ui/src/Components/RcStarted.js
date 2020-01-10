import React, { useState, useEffect } from 'react';
import { Button } from 'antd';
import { postJSON } from '../helpers.js';
import { serverURL } from '../config.js';

function RcStarted(props) {
  const loadingInit = props.loading;
  const startedInit = props.started;
  const service = props.service;
  const serviceURL = `${serverURL}/api/rc/${service}/started`;
  let [loadingSelf, setLoadingSelf] = useState(null);
  let [startedSelf, setStartedSelf] = useState(null);
  const loading = loadingSelf === null ? loadingInit : loadingSelf;
  const started = startedSelf === null ? startedInit : startedSelf;

  const handleClick = () => {
    console.log(`POST ${serviceURL} with ${!started}`);
    setLoadingSelf(true);
    postJSON(serviceURL, !started)
      .then((res) => {
        console.log(res);
        setStartedSelf(!started);
        setLoadingSelf(false);
      }).catch((res) => {
        console.warn(res);
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
