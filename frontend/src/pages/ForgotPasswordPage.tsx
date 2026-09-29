import { MailOutlined } from '@ant-design/icons';
import { App as AntApp, Button, Card, Form, Input, Typography } from 'antd';
import { useQuery } from '@tanstack/react-query';
import { useCallback, useState } from 'react';
import { Link } from 'react-router-dom';

import { authApi } from '../api/auth';
import { getApiErrorMessage } from '../api/client';
import { TurnstileWidget } from '../components/auth/TurnstileWidget';
import { PageTitle } from '../components/common/PageTitle';
import { Seo } from '../components/common/Seo';
import type { ForgotPasswordRequest } from '../types';

export function ForgotPasswordPage() {
  const { message } = AntApp.useApp();
  const [form] = Form.useForm<ForgotPasswordRequest>();
  const [submitting, setSubmitting] = useState(false);
  const [turnstileToken, setTurnstileToken] = useState<string | null>(null);
  const [turnstileReset, setTurnstileReset] = useState(0);
  const publicConfigQuery = useQuery({
    queryKey: ['auth', 'public-config'],
    queryFn: authApi.publicConfig,
  });
  const siteKey = publicConfigQuery.data?.turnstile_site_key;
  const setToken = useCallback((token: string | null) => setTurnstileToken(token), []);

  const submit = async (values: ForgotPasswordRequest) => {
    if (siteKey && !turnstileToken) {
      message.warning('请先完成人机验证');
      return;
    }
    setSubmitting(true);
    try {
      await authApi.forgotPassword({ ...values, turnstile_token: turnstileToken });
      message.success('密码重置邮件已发送，请检查邮箱');
      form.resetFields();
      setTurnstileReset((value) => value + 1);
    } catch (error) {
      message.error(getApiErrorMessage(error, '发送失败'));
      setTurnstileReset((value) => value + 1);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="auth-page">
      <Seo title="找回密码" noindex />
      <PageTitle title="找回密码" subtitle="输入注册邮箱，我们会发送密码重置链接。" />
      <Card className="auth-card">
        <Form<ForgotPasswordRequest> form={form} layout="vertical" onFinish={submit}>
          <Form.Item
            name="email"
            label="邮箱"
            rules={[
              { required: true, message: '请输入邮箱' },
              { type: 'email', message: '邮箱格式不正确' },
            ]}
          >
            <Input prefix={<MailOutlined />} autoComplete="email" />
          </Form.Item>
          <Form.Item label="人机验证" required={Boolean(siteKey)}>
            <TurnstileWidget
              siteKey={siteKey}
              action="forgot_password"
              resetSignal={turnstileReset}
              onToken={setToken}
            />
          </Form.Item>
          <Button type="primary" htmlType="submit" block loading={submitting || publicConfigQuery.isLoading}>
            发送重置邮件
          </Button>
        </Form>
        <Typography.Paragraph className="auth-switch">
          想起来了？<Link to="/signin">返回登录</Link>
        </Typography.Paragraph>
      </Card>
    </div>
  );
}
