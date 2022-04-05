import React, { useState } from 'react';
import { BrowserRouter as Router, Link, Route } from 'react-router-dom';
import { Layout, Menu } from 'antd';
import SideNav from './SideNav';
import MainContent from './MainContent';
import './App.css';

const {
  Header, Content, Footer, Sider,
} = Layout;
const { SubMenu } = Menu;

function App() {
  return (
    <div className="App">
      <Router>
        <Layout style={{ minHeight: '100vh' }}>
          <SideNav />
          <Layout>
            <Header />
            <Content>
              <MainContent />
            </Content>
          </Layout>
        </Layout>
      </Router>
    </div>
  );
}

function App1() {
  return (
    <Router>
      <div className="App">
        <ul className="App-links">
          <li><Link to="/">Home</Link></li>
          <li><Link to="/pf-states">States</Link></li>
          <li><Link to="/pf-rules">Rules</Link></li>
          <li><Link to="/pf-interfaces">Interfaces</Link></li>
          <li><Link to="netstat-interfaces">Netstat Interfaces</Link></li>
          <li><Link to="/rc">RC</Link></li>
          <li><Link to="/processes">Processes</Link></li>
          <li><Link to="/disk-usage">Disk Usage</Link></li>
          <li><Link to="/hardware">Hardware</Link></li>
          <li><Link to="/swap-usage">Swap usage</Link></li>
        </ul>
      </div>
    </Router>
  );
}

export default App;
