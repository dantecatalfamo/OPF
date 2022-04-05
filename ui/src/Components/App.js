import React from 'react';
import { BrowserRouter as Router } from 'react-router-dom';
import { Layout } from 'antd';
import SideNav from './SideNav';
import MainContent from './MainContent';
import './App.css';

const {
  Header, Content,
} = Layout;

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

export default App;
