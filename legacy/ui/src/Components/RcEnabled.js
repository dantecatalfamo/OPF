import React, { useState } from 'react';
import { Switch, message } from 'antd';
import { postJSON } from '../helpers.ts';
import { serverURL } from '../config.ts';

function RcEnabled(props) {
  const { enabled, loading } = props;
  const { onEnabled } = props;
  const { service } = props;
  const serviceURL = `${serverURL}/api/rc/${service}/enabled`;
  const [loadingSelf, setLoadingSelf] = useState(null);
  const shownLoading = loadingSelf === null ? loading : loadingSelf;

  const handleChange = () => {
    setLoadingSelf(true);
    postJSON(serviceURL, !enabled)
      .then((res) => {
        onEnabled(service, res);
        setLoadingSelf(false);
      }).catch(() => {
        message.error(`Failed to ${!enabled ? 'enable' : 'disable'} ${service}.`);
        setLoadingSelf(false);
      });
  };

  return (
    <Switch
      loading={shownLoading}
      checked={enabled}
      onChange={handleChange}
    />
  );
}

export default RcEnabled;
