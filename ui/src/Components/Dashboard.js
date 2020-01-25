import React, { useState, useEffect } from 'react';
import { Card } from 'antd';
import { getJSON, useJsonUpdates } from '../helpers';
import { serverURL } from '../config';

const unameURL = `${serverURL}/api/uname`;
const updateTime = 5000;

function Uname(props) {
  const [uname, setUname] = useState();

  useJsonUpdates(unameURL, setUname, updateTime);

  return (
    <Card title={uname ? uname.nodeName : ""} style={{width: 300, margin: 12}}>
      <p>OS Name: {uname ? `${uname.osName} ${uname.osRelease}` : ""}</p>
      <p>Platform: {uname ? `${uname.hardware}` : ""}</p>
    </Card>
  );
}

function Dashboard(props) {
  return (
    <div>
      <Uname/>
    </div>
  );
}

export default Dashboard;
