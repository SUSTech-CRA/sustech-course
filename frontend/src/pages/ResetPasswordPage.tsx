import { LockOutlined } from '@ant-design/icons';
import { App as AntApp, Button, Card, Form, Input, Result } from 'antd';
import { useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';

import { authApi } from '../api/auth';
import { getApiErrorMessage } from '../api/client';
import { PageTitle } from '../components/common/PageTitle';
import { Seo } from '../components/common/Seo';
import type { ResetPasswordRequest } from '../types';

export function ResetPasswordPage() {
  const { message } = AntApp.useApp();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const token = params.get('token');
  const [submitting, setSubmitting] = useState(false);

  if (!token) {
    return (
      <>
        <Seo title="重置密码" noindex />
        <Result
          status="error"
          title="重置链接无效"
          subTitle="链接中缺少 token，请重新发送密码重置邮件。"
          extra={<Button type="primary"><Link to="/forgot-password">重新发送</Link></Button>}
        />
      </>
    );
  }

  const submit = async (values: ResetPasswordRequest) => {
    setSubmitting(true);
    try {
      await authApi.resetPassword({ ...values, token });
      message.success('密码已经修改，请使用新密码登录');
      navigate('/signin', { replace: true });
    } catch (error) {
      message.error(getApiErrorMessage(error, '密码重置失败'));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="auth-page">
      <Seo title="重设密码" noindex />
      <PageTitle title="重设密码" subtitle="请输入新密码。" />
      <Card className="auth-card">
        <Form<ResetPasswordRequest> layout="vertical" onFinish={submit}>
          <Form.Item
            name="password"
            label="新密码"
            rules={[{ required: true, min: 8, message: '密码至少 8 位' }]}
          >
            <Input.Password prefix={<LockOutlined />} autoComplete="new-password" />
          </Form.Item>
          <Form.Item
            name="confirm_password"
            label="确认新密码"
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
          <Button type="primary" htmlType="submit" block loading={submitting}>
            更新密码
          </Button>
        </Form>
      </Card>
    </div>
  );
}
