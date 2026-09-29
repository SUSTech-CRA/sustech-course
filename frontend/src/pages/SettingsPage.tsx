import { UploadOutlined } from '@ant-design/icons';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { App as AntApp, Avatar, Button, Card, Form, Input, Result, Space, Spin, Switch, Upload } from 'antd';
import { useState } from 'react';

import { authApi } from '../api/auth';
import { getApiErrorMessage } from '../api/client';
import { uploadApi } from '../api/upload';
import { usersApi } from '../api/users';
import { PageTitle } from '../components/common/PageTitle';
import { Seo } from '../components/common/Seo';
import { useAuthStore } from '../stores/authStore';
import { FALLBACK_AVATAR } from '../utils/constants';
import type { ChangePasswordRequest, UserUpdate } from '../types';

export function SettingsPage() {
  const { message } = AntApp.useApp();
  const queryClient = useQueryClient();
  const user = useAuthStore((state) => state.user);
  const setUser = useAuthStore((state) => state.setUser);
  const setTokens = useAuthStore((state) => state.setTokens);
  const [passwordForm] = Form.useForm<ChangePasswordRequest>();
  const [avatarFile, setAvatarFile] = useState<File | null>(null);
  // 表单必须回填当前资料，否则保存时会把 homepage/简介/隐私开关清空
  const profileQuery = useQuery({
    queryKey: ['user', user?.id, 'settings-profile'],
    queryFn: () => usersApi.profile(user!.id),
    enabled: Boolean(user),
  });
  const updateMutation = useMutation({
    mutationFn: async (payload: UserUpdate) => {
      const nextPayload = { ...payload };
      if (avatarFile) {
        const uploaded = await uploadApi.image(avatarFile);
        nextPayload.avatar = uploaded.stored_filename;
      }
      return usersApi.updateMe(nextPayload);
    },
    onSuccess: (profile) => {
      setUser(profile);
      setAvatarFile(null);
      queryClient.invalidateQueries({ queryKey: ['user', user?.id] });
      message.success('设置已保存');
    },
    onError: (error) => message.error(getApiErrorMessage(error)),
  });
  const passwordMutation = useMutation({
    mutationFn: (payload: ChangePasswordRequest) => authApi.changePassword(payload),
    onSuccess: (tokens) => {
      // 改密后其他设备的登录全部失效，当前设备换用服务端新签发的令牌
      setTokens(tokens.access_token, tokens.refresh_token);
      message.success('密码已修改，其他设备需重新登录');
      passwordForm.resetFields();
    },
    onError: (error) => message.error(getApiErrorMessage(error)),
  });
  if (!user) {
    return <Result status="403" title="请先登录" />;
  }
  if (profileQuery.isLoading) {
    return <Spin fullscreen description="加载账号设置" />;
  }
  if (!profileQuery.data) {
    return <Result status="500" title="账号信息加载失败，请刷新重试" />;
  }

  const profile = profileQuery.data;

  return (
    <div>
      <Seo title="账号设置" noindex />
      <PageTitle title="账号设置" subtitle="更新主页资料和隐私开关。" />
      <Card className="section-card" title="个人资料">
        <Form<UserUpdate>
          layout="vertical"
          initialValues={{
            username: profile.username,
            homepage: profile.homepage || '',
            description: profile.description || '',
            is_following_hidden: Boolean(profile.is_following_hidden),
            is_profile_hidden: Boolean(profile.is_profile_hidden),
          }}
          onFinish={(values) => updateMutation.mutate(values)}
        >
          <Form.Item label="头像">
            <Space align="center">
              <Avatar size={48} src={(avatarFile && URL.createObjectURL(avatarFile)) || profile.avatar || FALLBACK_AVATAR} />
              <Upload
                accept="image/*"
                maxCount={1}
                showUploadList={false}
                beforeUpload={(file) => {
                  setAvatarFile(file);
                  return false;
                }}
              >
                <Button icon={<UploadOutlined />}>更换头像</Button>
              </Upload>
            </Space>
          </Form.Item>
          <Form.Item name="username" label="用户名">
            <Input />
          </Form.Item>
          <Form.Item name="homepage" label="个人主页">
            <Input />
          </Form.Item>
          <Form.Item name="description" label="个人简介">
            <Input.TextArea autoSize={{ minRows: 3, maxRows: 8 }} />
          </Form.Item>
          <Space size={24} wrap>
            <Form.Item name="is_following_hidden" label="隐藏关注列表" valuePropName="checked">
              <Switch />
            </Form.Item>
            <Form.Item name="is_profile_hidden" label="隐藏个人资料" valuePropName="checked">
              <Switch />
            </Form.Item>
          </Space>
          <Button type="primary" htmlType="submit" loading={updateMutation.isPending}>
            保存
          </Button>
        </Form>
      </Card>
      <Card className="section-card" title="修改密码">
        <Form<ChangePasswordRequest>
          form={passwordForm}
          layout="vertical"
          onFinish={(values) => passwordMutation.mutate(values)}
        >
          <Form.Item name="old_password" label="当前密码" rules={[{ required: true, message: '请输入当前密码' }]}>
            <Input.Password autoComplete="current-password" />
          </Form.Item>
          <Form.Item name="new_password" label="新密码" rules={[{ required: true, min: 8, message: '新密码至少 8 位' }]}>
            <Input.Password autoComplete="new-password" />
          </Form.Item>
          <Form.Item
            name="confirm_password"
            label="确认新密码"
            dependencies={['new_password']}
            rules={[
              { required: true, message: '请再次输入新密码' },
              ({ getFieldValue }) => ({
                validator(_rule, value) {
                  if (!value || value === getFieldValue('new_password')) return Promise.resolve();
                  return Promise.reject(new Error('两次输入的密码不一致'));
                },
              }),
            ]}
          >
            <Input.Password autoComplete="new-password" />
          </Form.Item>
          <Button type="primary" htmlType="submit" loading={passwordMutation.isPending}>
            修改密码
          </Button>
        </Form>
      </Card>
    </div>
  );
}
