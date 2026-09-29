import {
  BarChartOutlined,
  BellOutlined,
  BookOutlined,
  EditFilled,
  FireOutlined,
  HomeOutlined,
  InfoCircleOutlined,
  LoginOutlined,
  LogoutOutlined,
  MenuOutlined,
  ReadOutlined,
  SettingOutlined,
  TrophyOutlined,
  UserOutlined,
} from '@ant-design/icons';
import { Avatar, Badge, Button, Drawer, Dropdown, Menu, Space, Typography } from 'antd';
import type { MenuProps } from 'antd';
import { useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';

import { useAuth } from '../../hooks/useAuth';
import { buildSignInPath, buildSignUpPath, getRedirectFromLocation } from '../../utils/authRedirect';
import { FALLBACK_AVATAR } from '../../utils/constants';
import { NavSearch } from './NavSearch';

const SYLLABUS_PLAN_URL = 'https://mirrors.sustech.edu.cn/courses/本科人才培养方案/';

export function Navbar() {
  const navigate = useNavigate();
  const location = useLocation();
  const { user, logoutMutation } = useAuth();
  const [drawerOpen, setDrawerOpen] = useState(false);
  const currentRedirect = getRedirectFromLocation(location);
  const signInPath = buildSignInPath(currentRedirect);
  const signUpPath = buildSignUpPath(currentRedirect);

  const desktopMenuItems: MenuProps['items'] = [
    { key: '/', icon: <HomeOutlined />, label: <Link to="/">点评</Link> },
    { key: '/courses', icon: <BookOutlined />, label: <Link to="/courses">课程</Link> },
    {
      key: '/follow_reviews',
      icon: <FireOutlined />,
      disabled: !user,
      label: <Link to="/follow_reviews">关注</Link>,
    },
    { key: '/rankings', icon: <TrophyOutlined />, label: <Link to="/rankings">排行</Link> },
    {
      key: 'syllabus-plan',
      icon: <ReadOutlined />,
      label: (
        <a href={SYLLABUS_PLAN_URL} target="_blank" rel="noreferrer">
          培养方案
        </a>
      ),
    },
  ];

  const selectedKey = (() => {
    if (location.pathname.startsWith('/course')) return '/courses';
    if (location.pathname.startsWith('/rankings')) return '/rankings';
    if (location.pathname.startsWith('/stats')) return '/stats';
    if (location.pathname.startsWith('/about') || location.pathname.startsWith('/community-rules')) return '/about';
    if (location.pathname.startsWith('/follow_reviews')) return '/follow_reviews';
    return '/';
  })();

  const closeDrawer = () => setDrawerOpen(false);

  const drawerMenuItems: MenuProps['items'] = [
    { key: '/', icon: <HomeOutlined />, label: <Link to="/" onClick={closeDrawer}>点评</Link> },
    { key: '/courses', icon: <BookOutlined />, label: <Link to="/courses" onClick={closeDrawer}>课程</Link> },
    {
      key: '/follow_reviews',
      icon: <FireOutlined />,
      disabled: !user,
      label: <Link to="/follow_reviews" onClick={closeDrawer}>关注</Link>,
    },
    { key: '/rankings', icon: <TrophyOutlined />, label: <Link to="/rankings" onClick={closeDrawer}>排行</Link> },
    { key: '/stats', icon: <BarChartOutlined />, label: <Link to="/stats" onClick={closeDrawer}>统计</Link> },
    { key: '/about', icon: <InfoCircleOutlined />, label: <Link to="/about" onClick={closeDrawer}>关于</Link> },
    {
      key: 'syllabus-plan',
      icon: <ReadOutlined />,
      label: (
        <a href={SYLLABUS_PLAN_URL} target="_blank" rel="noreferrer" onClick={closeDrawer}>
          培养方案
        </a>
      ),
    },
  ];

  const userMenu: MenuProps['items'] = user
    ? [
        {
          key: 'profile',
          icon: <UserOutlined />,
          label: <Link to={`/user/${user.id}`}>个人主页</Link>,
        },
        {
          key: 'settings',
          icon: <SettingOutlined />,
          label: <Link to="/settings">设置</Link>,
        },
        {
          key: 'notifications',
          icon: <BellOutlined />,
          label: <Link to="/notifications">通知</Link>,
        },
        { type: 'divider' },
        {
          key: 'logout',
          icon: <LogoutOutlined />,
          label: '退出登录',
          onClick: () => logoutMutation.mutate(),
        },
      ]
    : [];

  return (
    <header className="app-header">
      <div className="header-inner">
        <Link to="/" className="brand">
          <span className="brand-mark"><EditFilled /></span>
          <span className="brand-text">Niuwa Curriculum Evaluation System</span>
        </Link>

        <Menu
          mode="horizontal"
          selectedKeys={[selectedKey]}
          items={desktopMenuItems}
          className="main-menu"
        />

        <NavSearch className="nav-search" />

        <div className="nav-account">
          {user ? (
            <Space>
              <Link to="/notifications">
                <Badge count={user.unread_notification_count} size="small">
                  <Button shape="circle" icon={<BellOutlined />} />
                </Badge>
              </Link>
              <Dropdown menu={{ items: userMenu }} trigger={['click']}>
                <Button className="user-menu-button">
                  <Space size={8}>
                    <Avatar size={24} src={user.avatar || FALLBACK_AVATAR} alt={user.username} />
                    <Typography.Text className="username">{user.username}</Typography.Text>
                  </Space>
                </Button>
              </Dropdown>
            </Space>
          ) : (
            <Space>
              <Button icon={<LoginOutlined />} onClick={() => navigate(signInPath)}>
                登录
              </Button>
              <Button type="primary" onClick={() => navigate(signUpPath)}>
                注册
              </Button>
            </Space>
          )}
        </div>

        <div className="mobile-actions">
          {user && (
            <Link to="/notifications">
              <Badge count={user.unread_notification_count} size="small">
                <Button shape="circle" icon={<BellOutlined />} />
              </Badge>
            </Link>
          )}
          <Button icon={<MenuOutlined />} onClick={() => setDrawerOpen(true)} aria-label="打开导航菜单" />
        </div>
      </div>
      <Drawer
        className="mobile-nav-drawer"
        title={
          <Link to="/" className="brand" onClick={closeDrawer}>
            <span className="brand-mark">N</span>
            <span className="brand-text">NCES</span>
          </Link>
        }
        placement="right"
        size="min(86vw, 360px)"
        open={drawerOpen}
        onClose={closeDrawer}
      >
        <Space orientation="vertical" size={16} className="full-width">
          <NavSearch className="full-width" onNavigated={closeDrawer} />
          <Menu mode="inline" selectedKeys={[selectedKey]} items={drawerMenuItems} />
          {user ? (
            <Space orientation="vertical" className="full-width">
              <Link to={`/user/${user.id}`} className="drawer-user-row" onClick={closeDrawer}>
                <Avatar size={36} src={user.avatar || FALLBACK_AVATAR} alt={user.username} />
                <Typography.Text strong>{user.username}</Typography.Text>
              </Link>
              <Button block icon={<BellOutlined />} onClick={() => { closeDrawer(); navigate('/notifications'); }}>
                通知 {user.unread_notification_count ? `(${user.unread_notification_count})` : ''}
              </Button>
              <Button block icon={<SettingOutlined />} onClick={() => { closeDrawer(); navigate('/settings'); }}>
                设置
              </Button>
              <Button
                block
                icon={<LogoutOutlined />}
                onClick={() => {
                  closeDrawer();
                  logoutMutation.mutate();
                }}
              >
                退出登录
              </Button>
            </Space>
          ) : (
            <Space className="full-width">
              <Button block icon={<LoginOutlined />} onClick={() => { closeDrawer(); navigate(signInPath); }}>
                登录
              </Button>
              <Button block type="primary" onClick={() => { closeDrawer(); navigate(signUpPath); }}>
                注册
              </Button>
            </Space>
          )}
        </Space>
      </Drawer>
    </header>
  );
}
