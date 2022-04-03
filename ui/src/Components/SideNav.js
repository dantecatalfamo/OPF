import React, { useState } from 'react';
import { Link, useLocation } from 'react-router-dom';

import {
  ApartmentOutlined,
  DashboardOutlined,
  FireOutlined,
  InfoCircleOutlined,
  LockOutlined,
  MonitorOutlined,
  SwapOutlined,
  ToolOutlined,
  ExceptionOutlined,
  DeploymentUnitOutlined,
} from '@ant-design/icons';

import { Layout, Menu } from 'antd';

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
    /* style={{ */
    /*   overflow: 'auto', */
    /*   height: '100vh', */
    /*   position: 'fixed', */
    /*   left: 0, */
    /* }} */
    >
      <div className="logo" />
      <Menu
        theme="dark"
        mode="inline"
        selectedKeys={[location.pathname]}
      >
        <Menu.Item key="/dashboard">
          <Link to="/dashboard">
            <DashboardOutlined />
            <span>Dashboard</span>
          </Link>
        </Menu.Item>
        <SubMenu
          key="firewall"
          title={
            <span>
              <FireOutlined />
              <span>Firewall</span>
            </span>
          }
        >
          <Menu.Item key="/firewall-info">
            <Link to="/firewall-info">
              <InfoCircleOutlined />
              <span>Info</span>
            </Link>
          </Menu.Item>
          <Menu.Item key="/firewall-states">
            <Link to="/firewall-states">
              <SwapOutlined />
              <span>States</span>
            </Link>
          </Menu.Item>
          <Menu.Item key="/firewall-rules">
            <Link to="/firewall-rules">
              <LockOutlined />
              <span>Rules</span>
            </Link>
          </Menu.Item>
          <Menu.Item key="/firewall-interfaces">
            <Link to="/firewall-interfaces">
              <ApartmentOutlined />
              <span>Interfaces</span>
            </Link>
          </Menu.Item>
        </SubMenu>
        <Menu.Item key="/services">
          <Link to="/services">
            <ToolOutlined />
            <span>Services</span>
          </Link>
        </Menu.Item>
        <Menu.Item key="/processes">
          <Link to="/processes">
            <MonitorOutlined />
            <span>Processes</span>
          </Link>
        </Menu.Item>
        <SubMenu
          key="logs"
          title={
            <span>
              <ExceptionOutlined />
              <span>Logs</span>
            </span>
          }
        >
          <Menu.Item key="/log/daemon">
            <Link to="/log/daemon">
              <span>Daemon</span>
            </Link>
          </Menu.Item>
          <Menu.Item key="/log/dmesg">
            <Link to="/log/dmesg">
              <span>Dmesg</span>
            </Link>
          </Menu.Item>
          <Menu.Item key="/log/messages">
            <Link to="/log/messages">
              <span>Messages</span>
            </Link>
          </Menu.Item>
          <Menu.Item key="/log/authlog">
            <Link to="/log/authlog">
              <span>Authlog</span>
            </Link>
          </Menu.Item>
        </SubMenu>
        <Menu.Item key="/wireguard">
          <Link to="/wireguard">
            <DeploymentUnitOutlined />
            <span>Wireguard</span>
          </Link>
        </Menu.Item>
      </Menu>
    </Sider>
  );
}

export default SideNav;
