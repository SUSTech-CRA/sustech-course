import { App as AntApp, Button, Result, Spin } from 'antd';
import { useEffect, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';

import { authApi } from '../api/auth';
import { getApiErrorMessage } from '../api/client';
import { Seo } from '../components/common/Seo';

export function ConfirmEmailPage() {
  const { message } = AntApp.useApp();
  const [params] = useSearchParams();
  const token = params.get('token');
  const handledRef = useRef(false);
  const [status, setStatus] = useState<'loading' | 'success' | 'error'>('loading');
  const [error, setError] = useState<string>('');

  useEffect(() => {
    if (handledRef.current) return;
    handledRef.current = true;
    if (!token) {
      setStatus('error');
      setError('激活链接缺少 token');
      return;
    }
    authApi
      .confirmEmail({ token })
      .then(() => {
        setStatus('success');
        message.success('邮箱激活成功，请登录');
      })
      .catch((err) => {
        setStatus('error');
        setError(getApiErrorMessage(err, '邮箱激活失败'));
      });
  }, [message, token]);

  if (status === 'loading') {
    return (
      <>
        <Seo title="邮箱激活" noindex />
        <Spin fullscreen description="正在激活邮箱" />
      </>
    );
  }

  if (status === 'success') {
    return (
      <>
        <Seo title="邮箱激活成功" noindex />
        <Result
          status="success"
          title="邮箱激活成功"
          extra={<Button type="primary"><Link to="/signin">去登录</Link></Button>}
        />
      </>
    );
  }

  return (
    <>
      <Seo title="邮箱激活失败" noindex />
      <Result status="error" title="邮箱激活失败" subTitle={error} />
    </>
  );
}
