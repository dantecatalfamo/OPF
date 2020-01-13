import React, { useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { Layout, Menu, Icon } from 'antd';

const { Header, Content, Footer, Sider } = Layout;
const { SubMenu } = Menu;

function SideNav(props) {
  const [collapsed, setCollapsed] = useState(false);
  const collapse = value => setCollapsed(value);

  const location = useLocation();

  return (
    <Sider
      collapsible
      collapsed={collapsed}
      onCollapse={collapse}
      style={{
        overflow: 'auto',
        height: '100vh',
        position: 'fixed',
        left: 0,
      }}
    >
      <div className="logo" />
      <Menu
        theme="dark"
        mode="inline"
        selectedKeys={[location.pathname]}
      >
        <Menu.Item key="/dashboard">
          <Link to="/dashboard">
            <Icon type="dashboard" />
            <span>Dashboard</span>
          </Link>
        </Menu.Item>
        <SubMenu
          key="firewall"
          title={
            <span>
              <Icon type="fire" />
              <span>Firewall</span>
            </span>
          }
        >
          <Menu.Item key="/firewall-info">
            <Link to="/firewall-info">
              <Icon type="info-circle"/>
              <span>Info</span>
            </Link>
          </Menu.Item>
          <Menu.Item key="/firewall-states">
            <Link to="/firewall-states">
              <Icon type="swap"/>
              <span>States</span>
            </Link>
          </Menu.Item>
          <Menu.Item key="/firewall-rules">
            <Link to="/firewall-rules">
              <Icon type="lock"/>
              <span>Rules</span>
            </Link>
          </Menu.Item>
          <Menu.Item key="/firewall-interfaces">
            <Link to="/firewall-interfaces">
              <Icon type="apartment" />
              <span>Interfaces</span>
            </Link>
          </Menu.Item>
        </SubMenu>
        <Menu.Item key="/services">
          <Link to="/services">
            <Icon type="tool"/>
            <span>Services</span>
          </Link>
        </Menu.Item>
      </Menu>
    </Sider>
  );
}

export default SideNav;
