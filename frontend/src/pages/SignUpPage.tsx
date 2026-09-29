import { LockOutlined, MailOutlined, RedoOutlined, UserOutlined } from '@ant-design/icons';
import { App as AntApp, Button, Card, Form, Input, Tooltip, Typography } from 'antd';
import { useMutation, useQuery } from '@tanstack/react-query';
import { useCallback, useEffect, useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';

import { authApi } from '../api/auth';
import { getApiErrorMessage } from '../api/client';
import { TurnstileWidget } from '../components/auth/TurnstileWidget';
import { PageTitle } from '../components/common/PageTitle';
import { Seo } from '../components/common/Seo';
import { useAuth } from '../hooks/useAuth';
import type { RegisterRequest } from '../types';
import { buildSignInPath, normalizeAuthRedirect } from '../utils/authRedirect';

export function SignUpPage() {
  const { message } = AntApp.useApp();
  const navigate = useNavigate();
  const location = useLocation();
  const { registerMutation } = useAuth();
  const [form] = Form.useForm<RegisterRequest>();
  const [turnstileToken, setTurnstileToken] = useState<string | null>(null);
  const [turnstileReset, setTurnstileReset] = useState(0);
  const publicConfigQuery = useQuery({
    queryKey: ['auth', 'public-config'],
    queryFn: authApi.publicConfig,
  });
  const siteKey = publicConfigQuery.data?.turnstile_site_key;
  const setToken = useCallback((token: string | null) => setTurnstileToken(token), []);
  const from = normalizeAuthRedirect(new URLSearchParams(location.search).get('next'));
  const signInPath = buildSignInPath(from);

  const suggestUsernameMutation = useMutation({
    mutationFn: () => authApi.suggestUsername(),
    onSuccess: (data) => form.setFieldValue('username', data.username),
  });
  useEffect(() => {
    suggestUsernameMutation.mutate();
    // suggest once on mount; the "换一个" button re-triggers it manually afterwards
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const submit = async (values: RegisterRequest) => {
    if (siteKey && !turnstileToken) {
      message.warning('请先完成人机验证');
      return;
    }
    try {
      await registerMutation.mutateAsync({ ...values, turnstile_token: turnstileToken });
      message.success('注册成功，请检查邮箱完成激活');
      navigate(signInPath);
    } catch (error) {
      message.error(getApiErrorMessage(error, '注册失败'));
      setTurnstileReset((value) => value + 1);
    }
  };

  return (
    <div className="auth-page">
      <Seo title="注册" noindex />
      <PageTitle title="注册" subtitle="请使用南科大邮箱注册。" />
      <Card className="auth-card">
        <Form<RegisterRequest> form={form} layout="vertical" onFinish={submit}>
          <Form.Item
            name="username"
            label="用户名"
            extra="已为你随机生成一个用户名，不会透露真实姓名，可以直接使用或自行修改。"
            rules={[{ required: true, message: '请输入用户名' }]}
          >
            <Input
              prefix={<UserOutlined />}
              autoComplete="username"
              suffix={
                <Tooltip title="换一个随机用户名">
                  <Button
                    type="text"
                    size="small"
                    icon={<RedoOutlined />}
                    loading={suggestUsernameMutation.isPending}
                    onClick={() => suggestUsernameMutation.mutate()}
                  />
                </Tooltip>
              }
            />
          </Form.Item>
          <Form.Item
            name="email"
            label="南科大邮箱（以 @mail.sustech.edu.cn 或 @sustech.edu.cn 结尾）"
            rules={[
              { required: true, message: '请输入南科大邮箱' },
              { type: 'email', message: '邮箱格式不正确' },
              {
                validator: (_, value) => {
                  if (!value || value.endsWith('@mail.sustech.edu.cn') || value.endsWith('@sustech.edu.cn')) {
                    return Promise.resolve();
                  }
                  return Promise.reject(new Error('请输入南科大邮箱'));
                },
              },
            ]}
          >
            <Input prefix={<MailOutlined />} autoComplete="email" />
          </Form.Item>
          <Form.Item
            name="password"
            label="密码"
            rules={[{ required: true, min: 8, message: '密码至少 8 位' }]}
          >
            <Input.Password prefix={<LockOutlined />} autoComplete="new-password" />
          </Form.Item>
          <Form.Item
            name="confirm_password"
            label="确认密码"
            dependencies={['password']}
            rules={[
              { required: true, message: '请再次输入密码' },
              ({ getFieldValue }) => ({
                validator(_, value) {
                  if (!value || getFieldValue('password') === value) return Promise.resolve();
                  return Promise.reject(new Error('两次输入的密码不一致'));
                },
              }),
            ]}
          >
            <Input.Password prefix={<LockOutlined />} autoComplete="new-password" />
          </Form.Item>
          <Form.Item label="人机验证" required={Boolean(siteKey)}>
            <TurnstileWidget
              siteKey={siteKey}
              action="signup"
              resetSignal={turnstileReset}
              onToken={setToken}
            />
          </Form.Item>
          <Button
            type="primary"
            htmlType="submit"
            block
            loading={registerMutation.isPending || publicConfigQuery.isLoading}
          >
            注册
          </Button>
        </Form>
        <Typography.Paragraph className="auth-switch">
          已有账号？<Link to={signInPath}>登录</Link>，或<Link to="/forgot-password">重设密码</Link>
        </Typography.Paragraph>
      </Card>
    </div>
  );
}
