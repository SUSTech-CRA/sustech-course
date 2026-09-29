import './instrument';

import * as Sentry from '@sentry/react';
import React from 'react';
import ReactDOM from 'react-dom/client';

import App from './App';
import './styles.css';

// 部署后旧标签页懒加载已删除的旧 chunk 会 404（vite:preloadError），自动整页刷新
// 一次以获取新 index。哨兵限一分钟内只自动刷一次：再次失败（部署损坏、持续网络
// 故障）时不拦截，让错误抛给 ErrorBoundary 提示用户，避免刷新循环。
window.addEventListener('vite:preloadError', (event) => {
  const RELOAD_AT_KEY = 'chunk-reload-at';
  try {
    const lastReloadAt = Number(sessionStorage.getItem(RELOAD_AT_KEY) || 0);
    if (Date.now() - lastReloadAt < 60_000) return;
    sessionStorage.setItem(RELOAD_AT_KEY, String(Date.now()));
  } catch {
    return; // 记录不了刷新时间就不自动刷（如禁用存储的环境），宁可走错误提示兜底
  }
  try {
    // keepalive 传输，刷新前通常能发出；用于监控部署撕裂的实际发生频率
    Sentry.captureMessage('chunk 加载失败，已自动刷新恢复', 'warning');
  } catch {
    /* Sentry 失败不阻塞恢复 */
  }
  event.preventDefault();
  window.location.reload();
});

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <Sentry.ErrorBoundary fallback={<p>页面组件加载失败，请刷新后重试。</p>}>
      <App />
    </Sentry.ErrorBoundary>
  </React.StrictMode>,
);
