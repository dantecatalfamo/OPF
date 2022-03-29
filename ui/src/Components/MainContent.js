import React from 'react';
import { BrowserRouter as Router, Routes, Link, Route } from 'react-router-dom';
import Dashboard from './Dashboard';
import PfInfo from './PfInfo';
import PfStates from './PfStates';
import PfRuleStates from './PfRuleStates';
import PfInterfaces from './PfInterfaces';
import NetstatInterfaces from './NetstatInterfaces';
import Processes from './Processes';
import Hardware from './Hardware';
import RC from './RC';

function MainContent(props) {
  return (
    <Routes>
      <Route path="/dashboard" element={<Dashboard/>} />
      <Route path="/firewall-info" element={<PfInfo/>} />
      <Route path="/firewall-states" element={<PfStates/>} />
      <Route path="/firewall-rules" element={<PfRuleStates/>} />
      <Route path="/firewall-interfaces" element={<PfInterfaces/>} />
      <Route path="/netstat-interfaces" element={<NetstatInterfaces/>} />
      <Route path="/services" element={<RC/>} />
      <Route path="/processes" element={<Processes/>} />
      <Route path="/hardware" element={<Hardware/>} />
      <Route path="/" render={"E"} />
    </Routes>
  );
}

export default MainContent;
