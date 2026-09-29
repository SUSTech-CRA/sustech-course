import { Alert, Spin } from 'antd';
import { useEffect, useRef, useState } from 'react';

type TurnstileInstance = {
  render: (
    element: HTMLElement,
    options: {
      sitekey: string;
      action?: string;
      callback: (token: string) => void;
      'expired-callback': () => void;
      'error-callback': () => void;
    },
  ) => string;
  remove: (widgetId: string) => void;
  reset: (widgetId: string) => void;
};

declare global {
  interface Window {
    turnstile?: TurnstileInstance;
  }
}

let turnstileScriptPromise: Promise<void> | null = null;

function loadTurnstileScript() {
  if (window.turnstile) return Promise.resolve();
  if (turnstileScriptPromise) return turnstileScriptPromise;

  turnstileScriptPromise = new Promise<void>((resolve, reject) => {
    const existing = document.getElementById('turnstile-script') as HTMLScriptElement | null;
    if (existing) {
      existing.addEventListener('load', () => resolve());
      existing.addEventListener('error', reject);
      return;
    }

    const script = document.createElement('script');
    script.id = 'turnstile-script';
    script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
    script.async = true;
    script.defer = true;
    script.onload = () => resolve();
    script.onerror = reject;
    document.head.appendChild(script);
  });

  return turnstileScriptPromise;
}

interface TurnstileWidgetProps {
  siteKey?: string;
  action: string;
  resetSignal?: number;
  onToken: (token: string | null) => void;
}

export function TurnstileWidget({ siteKey, action, resetSignal, onToken }: TurnstileWidgetProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const widgetIdRef = useRef<string | null>(null);
  const [loading, setLoading] = useState(Boolean(siteKey));
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    if (!siteKey) {
      onToken(null);
      setLoading(false);
      return undefined;
    }

    let cancelled = false;
    setLoading(true);
    setFailed(false);

    loadTurnstileScript()
      .then(() => {
        if (cancelled || !containerRef.current || !window.turnstile) return;
        widgetIdRef.current = window.turnstile.render(containerRef.current, {
          sitekey: siteKey,
          action,
          callback: (token) => onToken(token),
          'expired-callback': () => onToken(null),
          'error-callback': () => onToken(null),
        });
      })
      .catch(() => setFailed(true))
      .finally(() => setLoading(false));

    return () => {
      cancelled = true;
      if (widgetIdRef.current && window.turnstile) {
        window.turnstile.remove(widgetIdRef.current);
        widgetIdRef.current = null;
      }
    };
  }, [action, onToken, siteKey]);

  useEffect(() => {
    onToken(null);
    if (widgetIdRef.current && window.turnstile) {
      window.turnstile.reset(widgetIdRef.current);
    }
  }, [onToken, resetSignal]);

  if (!siteKey) {
    return <Alert type="info" showIcon title="开发环境未配置 Turnstile site key，已跳过人机验证组件。" />;
  }

  if (failed) {
    return <Alert type="error" showIcon title="人机验证组件加载失败，请刷新页面后重试。" />;
  }

  return (
    <div className="turnstile-box">
      {loading && <Spin size="small" />}
      <div ref={containerRef} />
    </div>
  );
}
