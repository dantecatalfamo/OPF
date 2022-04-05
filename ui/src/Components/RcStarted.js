import React, { useState, useEffect } from 'react';
import { Button, message, Popconfirm } from 'antd';
import { postJSON } from '../helpers.ts';
import { serverURL } from '../config.ts';

function RcStarted(props) {
  const loadingInit = props.loading;
  const { started } = props;
  const { enabled } = props;
  const { onStarted } = props;
  const { service } = props;
  const serviceURL = `${serverURL}/api/rc/${service}/started`;
  const [loadingSelf, setLoadingSelf] = useState(null);
  const loading = loadingSelf === null ? loadingInit : loadingSelf;

  const handleClick = () => {
    setLoadingSelf(true);
    postJSON(serviceURL, !started)
      .then((res) => {
        onStarted(service, res);
        setLoadingSelf(false);
      }).catch((res) => {
        message.error(`Failed to ${!started ? 'start' : 'stop'} ${service}. Check logs for details.`);
        setLoadingSelf(false);
      });
  };

  const startButton = enabled || started ? (
    <Button
      loading={loading}
      type={started ? 'danger' : 'primary'}
      onClick={handleClick}
    >
      {started ? 'Stop' : 'Start'}
    </Button>
  ) : (
    <Popconfirm
      title="Service not enabled, start without flags?"
      onConfirm={handleClick}
      okText="Yes"
      cancelText="No"
    >
      <Button
        loading={loading}
        type={started ? 'danger' : 'primary'}
      >
        {started ? 'Stop' : 'Start'}
      </Button>
    </Popconfirm>
  );

  return startButton;
}

export default RcStarted;
