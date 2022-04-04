import React, { useState, useCallback } from 'react';
import { Button, message } from 'antd';
import { postJSON } from '../helpers.js';
import { serverURL } from '../config.ts';

const pfKillIdURL = `${serverURL}/api/pf-kill-id`;

function PfKillID(props) {
  const id = props.id;
  const [submitting, setSubmitting] = useState(false);
  const [disabled, setDisabled] = useState(false);

  const handleClick = useCallback(() => {
    setSubmitting(true);
    postJSON(pfKillIdURL, id)
      .then(res => {
        setSubmitting(false);
        setDisabled(true); // disbable button until states update and row is removed
        message.success(`Killed state ${id}`);
      }).catch (res => {
        message.error(`Failed to kill state with ID ${id}`);
        setSubmitting(false);
      });
  }, [id]);

  return (
    <Button
      size="small"
      disabled={disabled}
      loading={submitting}
      onClick={handleClick}
    >Kill</Button>
  );
}

export default PfKillID;
