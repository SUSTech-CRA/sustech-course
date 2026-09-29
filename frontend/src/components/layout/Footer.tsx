import { useQuery } from '@tanstack/react-query';
import { Space, Typography } from 'antd';
import dayjs from 'dayjs';
import { useEffect, useMemo } from 'react';
import { Link } from 'react-router-dom';

import { metaApi } from '../../api/meta';
import { useAuthStore } from '../../stores/authStore';
import { parseApiTime } from '../../utils/format';
import { SentryFeedbackButton } from '../common/SentryFeedbackButton';

const footerLinks = [
  { to: '/about', label: '关于我们' },
  { to: '/community-rules', label: '社区规范' },
  { to: '/report-review', label: '投诉点评' },
  { to: '/stats', label: '站点统计' },
  { to: '/rankings', label: '排行榜' },
];

const adminFooterLinks = [
  { to: '/admin/banners', label: 'Banner 设置' },
  { to: '/admin/announcements', label: '公告管理' },
];

// 与老站相同的手动底部广告位（非 Auto Ads，仅此一处）；未配置时不渲染广告位
const ADSENSE_CLIENT = import.meta.env.VITE_ADSENSE_CLIENT;
const ADSENSE_SLOT = import.meta.env.VITE_ADSENSE_SLOT;
const ADSENSE_ENABLED = Boolean(ADSENSE_CLIENT && ADSENSE_SLOT);
// 广告脚本推迟到 window.load 后 3s 再注入，完全让出冷启动带宽与主线程
// （页脚位在首屏之外，晚几秒填充无感知）。模块级标记：Footer 在 AppLayout
// 常驻，整页生命周期只初始化一次，且异步调度下 dataset 标记会被 StrictMode
// 双跑的 cleanup 破坏，故用模块变量。
const ADSENSE_INIT_DELAY_MS = 3000;
let adInitScheduled = false;

function initAdsense() {
  if (!document.querySelector('script[src^="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js"]')) {
    const script = document.createElement('script');
    script.async = true;
    script.crossOrigin = 'anonymous';
    script.src = `https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=${ADSENSE_CLIENT}`;
    document.head.appendChild(script);
  }
  try {
    const w = window as unknown as { adsbygoogle?: unknown[] };
    (w.adsbygoogle = w.adsbygoogle || []).push({});
  } catch {
    // 屏蔽插件/网络不可达时静默失败，容器由 CSS 按 unfilled 状态收起
  }
}

export function Footer() {
  const isAdmin = useAuthStore((state) => state.user?.role === 'Admin');

  useEffect(() => {
    if (adInitScheduled || !ADSENSE_ENABLED) return;
    adInitScheduled = true;
    const schedule = () => window.setTimeout(initAdsense, ADSENSE_INIT_DELAY_MS);
    if (document.readyState === 'complete') {
      schedule();
    } else {
      window.addEventListener('load', schedule, { once: true });
    }
  }, []);
  const requestInfoQuery = useQuery({
    queryKey: ['meta', 'request-info'],
    queryFn: metaApi.requestInfo,
    staleTime: 60 * 1000,
    refetchInterval: 60 * 1000,
  });

  const debugText = useMemo(() => {
    const time =
      parseApiTime(requestInfoQuery.data?.server_time)?.format('YYYYMMDD HH:mm:ss') ||
      dayjs().format('YYYYMMDD HH:mm:ss');
    return `${time} | ${requestInfoQuery.data?.client_ip || 'IP未知'}`;
  }, [requestInfoQuery.data]);

  return (
    <footer className="app-footer">
      {ADSENSE_ENABLED && (
        <div className="footer-ad">
          <ins
            className="adsbygoogle"
            style={{ display: 'block', minWidth: 300, maxWidth: 970, width: '100%', height: 103 }}
            data-ad-client={ADSENSE_CLIENT}
            data-ad-slot={ADSENSE_SLOT}
          />
        </div>
      )}
      <Space className="footer-nav" size={[18, 8]} wrap>
        {footerLinks.map((item) => (
          <Link key={item.to} to={item.to}>
            {item.label}
          </Link>
        ))}
        {/* put sentry link here */ }
        <SentryFeedbackButton source="home_quick_entry" />
        {isAdmin &&
          adminFooterLinks.map((item) => (
            <Link key={item.to} to={item.to}>
              {item.label}
            </Link>
          ))}
      </Space>
      <Typography.Text className="footer-debug mono-text" copyable={{ text: debugText }}>
        {debugText}
      </Typography.Text>
      <Typography.Text type="secondary">
        Copyright © 2022 - {dayjs().year()} Niuwa Curriculum Evaluation System
      </Typography.Text>
    </footer>
  );
}
