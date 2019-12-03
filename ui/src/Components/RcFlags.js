import React, { useState, useEffect } from 'react';
import { Popover, Button, Input, Form } from 'antd';
import { getJSON } from '../helpers.js';
import { serverURL } from '../config.js';

function RcFlags (props) {
  const disabled = props.disabled;
  const loading = props.loading;
  const service = props.service;
  const flagsURL = `${serverURL}/api/rc/${service}/flags`;

  const [flags, setFlags] = useState();
  const [visible, setVisible] = useState();

  const handleVisibleChange = visible => {
    setVisible(visible);
  };

  const handleFlagsChange = (event) => {
    setFlags(event.target.value);
  };

  useEffect(() => {
    if (visible) {
      getJSON(flagsURL).then(f => setFlags(f));
    }
  }, [visible]);

  const flagsButton = (
    <Button
      disabled={disabled}
      loading={loading}
    >Flags</Button>
  );

  if (disabled) {
    return flagsButton;
  }

  const content = (
      <Form layout="inline">
        <Form.Item>
          <Input
            value={flags}
            onChange={handleFlagsChange}
          />
        </Form.Item>
        <Form.Item style={{marginRight: 0}}>
          <Button>Save</Button>
        </Form.Item>
      </Form>
  );

  return (
    <Popover
      // title={service + " flags"}
      content={content}
      placement="right"
      trigger="click"
      visible={visible}
      onVisibleChange={handleVisibleChange}
    >
      {flagsButton}
    </Popover>
  );
}

export default RcFlags;
