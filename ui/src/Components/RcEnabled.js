import React, { useState, useEffect } from 'react';
import { Switch, message } from 'antd';
import { postJSON } from '../helpers.ts';
import { serverURL } from '../config.ts';

function RcEnabled(props) {
  const enabled = props.enabled;
  const loadingInit = props.loading;
  const onEnabled = props.onEnabled;
  const service = props.service;
  const serviceURL = `${serverURL}/api/rc/${service}/enabled`;
  const [loadingSelf, setLoadingSelf] = useState(null);
  const loading = loadingSelf === null ? loadingInit : loadingSelf;

  const handleChange = () => {
    setLoadingSelf(true);
    postJSON(serviceURL, !enabled)
      .then(res => {
        onEnabled(service, res);
        setLoadingSelf(false);
      }).catch(res => {
        message.error(`Failed to ${!enabled ? "enable" : "disable"} ${service}.`);
        setLoadingSelf(false);
      });
  };

  return (
    <Switch
      loading={loading}
      checked={enabled}
      onChange={handleChange}
    />
  );


}

export default RcEnabled;
