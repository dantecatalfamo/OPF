import React from 'react';
import { BrowserRouter as Router, Switch, Link, Route } from 'react-router-dom';
import PfStates from './PfStates';
import PfRuleStates from './PfRuleStates';
import PfInterfaces from './PfInterfaces';
import NetstatInterfaces from './NetstatInterfaces';
import Uptime from './Uptime';
import './App.css';

function App() {
  return (
    <Router>
      <div className="App">
        <Uptime/>
        <ul className="App-links">
          <li><Link to="/">Home</Link></li>
          <li><Link to="/pf-states">States</Link></li>
          <li><Link to="/pf-rules">Rules</Link></li>
          <li><Link to="/pf-interfaces">Interfaces</Link></li>
          <li><Link to="netstat-interfaces">Netstat Interfaces</Link></li>
        </ul>
        <Switch>
          <Route path="/pf-states">
            <PfStates/>
          </Route>
          <Route path="/pf-rules">
            <PfRuleStates/>
          </Route>
          <Route path="/pf-interfaces">
            <PfInterfaces/>
          </Route>
          <Route path="/netstat-interfaces">
            <NetstatInterfaces/>
          </Route>
          <Route path="/">
            <p>
              Hello!
            </p>
          </Route>
        </Switch>
      </div>
    </Router>
      );
}


export default App;
