import { LoginOutlined, LockOutlined, MailOutlined, UserOutlined } from '@ant-design/icons';
import { Alert, App as AntApp, Button, Card, Checkbox, Divider, Form, Input, Typography } from 'antd';
import { useMutation, useQuery } from '@tanstack/react-query';
import axios from 'axios';
import { useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';

import { authApi } from '../api/auth';
import { getApiErrorMessage } from '../api/client';
import { PageTitle } from '../components/common/PageTitle';
import { Seo } from '../components/common/Seo';
import { useAuth } from '../hooks/useAuth';
import type { LoginRequest } from '../types';
import { buildSignUpPath, normalizeAuthRedirect } from '../utils/authRedirect';

export function SignInPage() {
  const { message } = AntApp.useApp();
  const navigate = useNavigate();
  const location = useLocation();
  const { loginMutation } = useAuth();
  const [unconfirmedLogin, setUnconfirmedLogin] = useState<string | null>(null);
  const params = new URLSearchParams(location.search);
  const stateFrom = (location.state as { from?: string } | null)?.from;
  const from = normalizeAuthRedirect(params.get('next') || stateFrom);
  const oauthError = params.get('oauth_error');
  const signUpPath = buildSignUpPath(from);
  const resendMutation = useMutation({
    mutationFn: (login: string) => authApi.resendConfirmation(login),
    onSuccess: () => message.success('激活邮件已重新发送，请到邮箱查收'),
    onError: (error) => message.error(getApiErrorMessage(error, '激活邮件发送失败')),
  });
  const publicConfigQuery = useQuery({
    queryKey: ['auth', 'public-config'],
    queryFn: authApi.publicConfig,
  });
  const oauthUrl = `${publicConfigQuery.data?.oauth_cra_url || '/api/v1/auth/oauth/cra'}?next=${encodeURIComponent(from)}&frontend_origin=${encodeURIComponent(window.location.origin)}`;

  const submit = async (values: LoginRequest) => {
    setUnconfirmedLogin(null);
    try {
      await loginMutation.mutateAsync(values);
      message.success('登录成功');
      navigate(from, { replace: true });
    } catch (error) {
      const detail = getApiErrorMessage(error, '登录失败');
      // 未激活账号：提供重发激活邮件入口（与老版登录页一致）
      if (axios.isAxiosError(error) && error.response?.status === 403 && detail.includes('激活')) {
        setUnconfirmedLogin(values.username);
      }
      message.error(detail);
    }
  };

  return (
    <div className="auth-page">
      <Seo title="登录" noindex />
      <PageTitle title="登录" subtitle="使用用户名或南科大邮箱登录。" />
      <Card className="auth-card">
        {oauthError && (
          <Alert className="auth-alert" type="error" showIcon title="SSO 登录失败" description={oauthError} />
        )}
        <Form<LoginRequest> layout="vertical" onFinish={submit} initialValues={{ remember: true }}>
          <Form.Item name="username" label="用户名或邮箱" rules={[{ required: true, message: '请输入用户名或邮箱' }]}>
            <Input prefix={<UserOutlined />} autoComplete="username" />
          </Form.Item>
          <Form.Item name="password" label="密码" rules={[{ required: true, message: '请输入密码' }]}>
            <Input.Password prefix={<LockOutlined />} autoComplete="current-password" />
          </Form.Item>
          <Form.Item name="remember" valuePropName="checked">
            <Checkbox>记住我</Checkbox>
          </Form.Item>
          <Button type="primary" htmlType="submit" block loading={loginMutation.isPending}>
            登录
          </Button>
        </Form>
        {unconfirmedLogin && (
          <Alert
            className="auth-alert"
            type="warning"
            showIcon
            title="账号尚未激活"
            description="请点击邮箱里的激活链接。如果没有收到邮件（可能在垃圾箱中），可以重新发送。"
            action={
              <Button
                size="small"
                icon={<MailOutlined />}
                loading={resendMutation.isPending}
                onClick={() => resendMutation.mutate(unconfirmedLogin)}
              >
                重发激活邮件
              </Button>
            }
          />
        )}
        <div className="auth-row">
          <Link to="/forgot-password">忘记密码？</Link>
        </div>
        <Divider plain>或</Divider>
        <Button
          block
          icon={<LoginOutlined />}
          href={oauthUrl}
          disabled={publicConfigQuery.isLoading || publicConfigQuery.data?.oauth_cra_enabled === false}
        >
          CRA SSO / SUSTech CAS 登录/注册
        </Button>
        <Typography.Paragraph className="auth-switch">
          还没有账号？<Link to={signUpPath}>注册</Link>
        </Typography.Paragraph>
      </Card>
    </div>
  );
}
