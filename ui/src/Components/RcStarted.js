import React, { useState, useEffect } from 'react';
import { Button } from 'antd';

function RcStarted(props) {
  const loadingInit = props.loading;
  const startedInit = props.started;
  let [loadingSelf, setLoadingSelf] = useState(null);
  let [startedSelf, setStartedSelf] = useState(null);
  const loading = loadingSelf === null ? loadingInit : loadingSelf;
  const started = startedSelf === null ? startedInit : startedSelf;

  return (
    <Button
      loading={loading}
      type={started ? "danger" : "primary"}
    >
      {started ? "Stop" : "Start"}
    </Button>
  );
}

export default RcStarted;
