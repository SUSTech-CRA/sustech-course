import * as Sentry from '@sentry/react';
import React from 'react';
import {
  createRoutesFromChildren,
  matchRoutes,
  useLocation,
  useNavigationType,
} from 'react-router-dom';

// 未配置 DSN 时不初始化 Sentry（fork 部署默认不上报；反馈按钮随之隐藏）
export const sentryDsn = import.meta.env.VITE_SENTRY_DSN;

if (sentryDsn) Sentry.init({
  dsn: sentryDsn,
  environment: import.meta.env.MODE,
  release: import.meta.env.VITE_APP_VERSION,
  dataCollection: {
    userInfo: true,
    cookies: false,
    httpHeaders: {
      request: { deny: ['authorization', 'cookie'] },
      response: { deny: ['set-cookie'] },
    },
    httpBodies: [],
    genAI: { inputs: false, outputs: false },
    stackFrameVariables: false,
  },
  integrations: [
    Sentry.reactRouterV6BrowserTracingIntegration({
      useEffect: React.useEffect,
      useLocation,
      useNavigationType,
      createRoutesFromChildren,
      matchRoutes,
    }),
    Sentry.feedbackAsyncIntegration({
      autoInject: false,
      showBranding: false,
      enableScreenshot: true,
      colorScheme: 'system',
      triggerLabel: '反馈问题',
      triggerAriaLabel: '反馈问题',
      formTitle: '反馈问题',
      nameLabel: '称呼',
      namePlaceholder: '如何称呼你',
      emailLabel: '邮箱',
      emailPlaceholder: '方便我们联系你的邮箱',
      messageLabel: '问题描述',
      messagePlaceholder: '哪里出了问题？你原本期待看到什么？',
      submitButtonLabel: '提交反馈',
      cancelButtonLabel: '取消',
      addScreenshotButtonLabel: '添加截图',
      removeScreenshotButtonLabel: '移除截图',
      highlightToolText: '标记',
      hideToolText: '遮挡',
      removeHighlightText: '移除标记',
      successMessageText: '谢谢反馈，我们会尽快查看。',
      errorEmptyMessageText: '请先填写问题描述。',
      errorGenericText: '反馈提交失败，可能是网络或浏览器插件拦截。',
      tags: {
        app: 'ncesnext-frontend',
      },
    }),
  ],
  // 生产默认 15% 采样（每次访问都发 transaction 太耗配额且无必要），开发全量便于调试
  tracesSampleRate: Number(import.meta.env.VITE_SENTRY_TRACES_SAMPLE_RATE ?? (import.meta.env.PROD ? 0.15 : 1.0)),
  tracePropagationTargets: [
    'localhost',
    /^\/api\//,
    /^https:\/\/beta\.ncesnext\.com\/api\//,
    /^https:\/\/dev\.ncesnext\.com\/api\//,
  ],
  enableLogs: true,
});
