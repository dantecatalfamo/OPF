import React, { useState, useEffect } from 'react';
import { Form } from '@ant-design/compatible';
import '@ant-design/compatible/assets/index.css';
import { Popover, Button, Input, Spin, message } from 'antd';
import { getJSON, postJSON } from '../helpers.js';
import { serverURL } from '../config.ts';

function RcFlags (props) {
  const disabled = props.disabled;
  const loading = props.loading;
  const service = props.service;
  const flagsURL = `${serverURL}/api/rc/${service}/flags`;

  const [flags, setFlags] = useState();
  const [visible, setVisible] = useState();
  const [fetching, setFetching] = useState(true);
  const [submitting, setSubmitting] = useState(false);

  const handleVisibleChange = visible => {
    setVisible(visible);
  };

  const handleFlagsChange = (event) => {
    setFlags(event.target.value);
  };

  useEffect(() => {
    if (visible) {
      setFetching(true);
      getJSON(flagsURL).then(f => {
        setFlags(f);
        setFetching(false);
      });
    }
  }, [visible]);

  const handleSave = () => {
    setSubmitting(true);
    postJSON(flagsURL, flags)
      .then(res => {
        message.success("Flags saves successfully.");
        setSubmitting(false);
      }).catch(res => {
        message.error(`Failed to set ${service} flags.`);
        setSubmitting(false);
      });
  };

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
    <Spin spinning={fetching}>
      <Form layout="inline">
        <Form.Item>
          <Input
            value={flags}
            disabled={fetching}
            onChange={handleFlagsChange}
          />
        </Form.Item>
        <Form.Item style={{marginRight: 0}}>
          <Button
            disabled={fetching}
            loading={submitting}
            onClick={handleSave}
          >Save</Button>
        </Form.Item>
      </Form>
    </Spin>
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
