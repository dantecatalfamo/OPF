import React, { useState, useCallback } from 'react';
import { Button, message } from 'antd';
import { postJSON } from '../helpers.ts';
import { serverURL } from '../config.ts';

const pfKillIdURL = `${serverURL}/api/pf-kill-id`;

function PfKillID(props) {
  const { id } = props;
  const [submitting, setSubmitting] = useState(false);
  const [disabled, setDisabled] = useState(false);

  const handleClick = useCallback(() => {
    setSubmitting(true);
    postJSON(pfKillIdURL, id)
      .then(() => {
        setSubmitting(false);
        setDisabled(true); // disbable button until states update and row is removed
        message.success(`Killed state ${id}`);
      }).catch(() => {
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
    >
      Kill
    </Button>
  );
}

export default PfKillID;
