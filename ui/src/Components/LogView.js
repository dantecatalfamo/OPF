import React from 'react';
import { useState, useEffect } from 'react';
import { Typography } from 'antd';
import { serverURL } from '../config';
import './LogView.css';

const { Paragraph } = Typography;

const updateTime = 30 * 1000;

function LogView(props) {
  const { log } = props;
  const [logContents, setLogContents] = useState("");

  const url = `${serverURL}/api/logs/${log}`;

  useEffect(() => {
    fetch(url).then(res => res.text()).then(text => setLogContents(text));
    const interval = setInterval(() => {
      fetch(url).then(res => res.text()).then(text => setLogContents(text));
    }, updateTime);

    return () => clearInterval(interval);
  }, [url, updateTime]);

  return (
    <code className="logview">
      {logContents}
    </code>
  );
}

export default LogView;
