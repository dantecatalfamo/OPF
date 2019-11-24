import React from 'react';
import { BrowserRouter as Router, Switch, Link, Route } from 'react-router-dom';
import PfStates from './PfStates';
import PfRuleStates from './PfRuleStates';
import PfInterfaces from './PfInterfaces';
import './App.css';

function App() {
  return (
    <Router>
      <div className="App">
        <Link to="/">Home</Link>
        <Link to="/states">States</Link>
        <Link to="/rules">Rules</Link>
        <Link to="/interfaces">Interfaces</Link>
        <Link to=""/>
        <Switch>
          <Route path="/states">
            <PfStates/>
          </Route>
          <Route path="/rules">
            <PfRuleStates/>
          </Route>
          <Route path="/interfaces">
            <PfInterfaces/>
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
