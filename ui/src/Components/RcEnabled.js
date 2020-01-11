import React, { useState, useEffect } from 'react';
import { Switch, notification } from 'antd';
import { postJSON } from '../helpers.js';
import { serverURL } from '../config.js';

function RcEnabled(props) {
  const enabled = props.enabled;
  const loadingInit = props.loading;
  const onEnabled = props.onEnabled;
  const service = props.service;
  const serviceURL = `${serverURL}/api/rc/${service}/enabled`;
  const [loadingSelf, setLoadingSelf] = useState(null);
  const loading = loadingSelf === null ? loadingInit : loadingSelf;

  const handleChange = () => {
    console.log(`POST ${serviceURL} with ${!enabled}`);
    setLoadingSelf(true);
    postJSON(serviceURL, !enabled)
      .then(res => {
        onEnabled(service, res);
        setLoadingSelf(false);
      }).catch(res => {
        notification['error']({
          message: "Error",
          description: `Failed to enable ${service}.`,
        });
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
