import React, { useState, useEffect } from 'react';
import { getJSON } from '../helpers.js';
import { serverURL } from '../config.js';
import './Uname.css';

const unameURL = `${serverURL}/api/uname`;
const newTitle = "OPF";

function Uname() {
  const [uname, setUname] = useState(null);

  useEffect(() => {
    getJSON(unameURL).then(res => setUname(res));
  }, []);

  useEffect(() => {
    if (uname) {
      document.title = `${uname.osName} (${uname.nodeName})`;
    } else {
      document.title = newTitle;
    }
  }, [uname]);

  if (!uname) {
    return "OS VERSION";
  }
  return (
    <div className="uname">
      <div className="uname-osname">{uname.osName}</div>
      <div className="uname-osrelease">{uname.osRelease}</div>
      <div className="uname-nodename">{uname.nodeName}</div>
    </div>
  );
}

export default Uname;
