import { App as AntApp, Result, Spin } from 'antd';
import { useQueryClient } from '@tanstack/react-query';
import { useEffect, useRef, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';

import { authApi } from '../api/auth';
import { Seo } from '../components/common/Seo';
import { useAuthStore } from '../stores/authStore';
import { resetQueriesForAuthenticatedUser } from '../utils/authCache';
import { normalizeAuthRedirect } from '../utils/authRedirect';

export function OAuthCallbackPage() {
  const location = useLocation();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { message } = AntApp.useApp();
  const handledRef = useRef(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (handledRef.current) return;
    handledRef.current = true;

    const params = new URLSearchParams(location.hash.replace(/^#/, ''));
    const accessToken = params.get('access_token');
    const refreshToken = params.get('refresh_token');
    const next = normalizeAuthRedirect(params.get('next'));

    if (!accessToken || !refreshToken) {
      setError('SSO 回调缺少登录凭据');
      return;
    }

    useAuthStore.getState().setTokens(accessToken, refreshToken);
    authApi
      .me()
      .then((user) => {
        useAuthStore.getState().login(user, accessToken, refreshToken);
        resetQueriesForAuthenticatedUser(queryClient, user);
        message.success('SSO 登录成功');
        navigate(next, { replace: true });
      })
      .catch(() => {
        useAuthStore.getState().logout();
        setError('SSO 登录凭据验证失败，请重新登录');
      });
  }, [location.hash, message, navigate, queryClient]);

  if (error) {
    return (
      <>
        <Seo title="SSO 登录失败" noindex />
        <Result status="error" title="SSO 登录失败" subTitle={error} />
      </>
    );
  }

  return (
    <>
      <Seo title="SSO 登录中" noindex />
      <Spin fullscreen description="正在完成 SSO 登录" />
    </>
  );
}
