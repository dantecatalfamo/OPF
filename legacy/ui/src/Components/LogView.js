import React, { useState, useEffect } from 'react';
import { serverURL } from '../config';
import './LogView.css';

const updateTime = 30 * 1000;

function LogView(props) {
  const { log } = props; // eslint-disable-line react/prop-types
  const [logContents, setLogContents] = useState('');

  const url = `${serverURL}/api/logs/${log}`;

  useEffect(() => {
    fetch(url).then((res) => res.text()).then((text) => setLogContents(text));
    const interval = setInterval(() => {
      fetch(url).then((res) => res.text()).then((text) => setLogContents(text));
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
