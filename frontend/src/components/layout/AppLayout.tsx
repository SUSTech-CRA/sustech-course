import { Layout } from 'antd';
import { Outlet } from 'react-router-dom';

import { BannerStrip } from './BannerStrip';
import { Footer } from './Footer';
import { Navbar } from './Navbar';

export function AppLayout() {
  return (
    <Layout className="app-shell">
      <Navbar />
      <BannerStrip />
      <Layout.Content className="app-content">
        <Outlet />
      </Layout.Content>
      <Footer />
    </Layout>
  );
}
