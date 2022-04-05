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
    <Router>
      <div className="App">
        <Layout style={{ minHeight: '100vh' }}>
          <SideNav />
          <Layout>
            <Header />
            <Content>
              <MainContent />
            </Content>
          </Layout>
        </Layout>
      </div>
    </Router>
  );
}

export default App;
