import React from 'react';
import { BrowserRouter as Router, Switch, Link, Route } from 'react-router-dom';
import PfInfo from './PfInfo';
import PfStates from './PfStates';
import PfRuleStates from './PfRuleStates';
import PfInterfaces from './PfInterfaces';
import NetstatInterfaces from './NetstatInterfaces';
import Uptime from './Uptime';
import Uname from './Uname';
import Processes from './Processes';
import DiskUsage from './DiskUsage';
import Hardware from './Hardware';
import SwapUsage from './SwapUsage';
import RC from './RC';

function MainContent(props) {
  return (
    <Switch>
      <Route path="/firewall-info">
        <PfInfo/>
      </Route>
      <Route path="/firewall-states">
        <PfStates/>
      </Route>
      <Route path="/firewall-rules">
        <PfRuleStates/>
      </Route>
      <Route path="/firewall-interfaces">
        <PfInterfaces/>
      </Route>
      <Route path="/netstat-interfaces">
        <NetstatInterfaces/>
      </Route>
      <Route path="/services">
        <RC/>
      </Route>
      <Route path="/processes">
        <Processes/>
      </Route>
      <Route path="/disk-usage">
        <DiskUsage/>
      </Route>
      <Route path="/hardware">
        <Hardware/>
      </Route>
      <Route path="/swap-usage">
        <SwapUsage/>
      </Route>
      <Route path="/">
        <p>
          Hello!
        </p>
      </Route>
    </Switch>
  );
}

export default MainContent;
