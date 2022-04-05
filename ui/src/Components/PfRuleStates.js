import React, { useState, useEffect } from 'react';
import { getJSON, useJsonUpdates } from '../helpers.ts';
import { serverURL } from '../config.ts';
import './PfRuleStates.css';

const pfRuleStatesURL = `${serverURL}/api/pf-rule-states`;
const updateTime = 2000;

function PfRuleStates() {
  const [rulestates, setRulestates] = useState([]);

  useJsonUpdates(pfRuleStatesURL, setRulestates, updateTime);

  return (
    <div className="pfrulestates">
      <table>
        <thead>
          <tr>
            <th>Number</th>
            <th>Rule</th>
            <th>Packets</th>
            <th>Bytes</th>
            <th>States</th>
            <th>Evaluations</th>
            <th>State Creations</th>
          </tr>
        </thead>
        <tbody>
          {rulestates.map((rule) => (
            <tr key={rule.number}>
              <td>{rule.number}</td>
              <td>{rule.rule}</td>
              <td>{rule.packets}</td>
              <td>{rule.bytes}</td>
              <td>{rule.states}</td>
              <td>{rule.evaluations}</td>
              <td>{rule.stateCreations}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default PfRuleStates;
