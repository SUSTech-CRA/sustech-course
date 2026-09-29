import { UploadOutlined } from '@ant-design/icons';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Alert,
  App as AntApp,
  Button,
  Card,
  Form,
  Input,
  Result,
  Space,
  Spin,
  Switch,
  Table,
  Upload,
} from 'antd';
import type { UploadFile } from 'antd';
import { useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';

import { getApiErrorMessage } from '../api/client';
import { teachersApi } from '../api/teachers';
import { uploadApi } from '../api/upload';
import { PageTitle } from '../components/common/PageTitle';
import { Seo } from '../components/common/Seo';
import { useAuthStore } from '../stores/authStore';
import { formatDateTime } from '../utils/format';
import type { TeacherHistoryResponse, TeacherUpdate } from '../types';

export function TeacherEditPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { message } = AntApp.useApp();
  const user = useAuthStore((state) => state.user);
  const [avatarFile, setAvatarFile] = useState<File | null>(null);
  const teacherQuery = useQuery({
    queryKey: ['teacher', id],
    queryFn: () => teachersApi.detail(id as string),
    enabled: Boolean(id),
  });
  const historyQuery = useQuery({
    queryKey: ['teacher', id, 'history'],
    queryFn: () => teachersApi.history(id as string),
    enabled: Boolean(id),
  });
  const updateMutation = useMutation({
    mutationFn: async (payload: TeacherUpdate) => {
      const nextPayload = { ...payload };
      if (avatarFile) {
        const uploaded = await uploadApi.image(avatarFile);
        nextPayload.image = uploaded.stored_filename;
      }
      return teachersApi.update(id as string, nextPayload);
    },
    onSuccess: (teacher) => {
      queryClient.invalidateQueries({ queryKey: ['teacher', String(teacher.id)] });
      message.success('教师信息已保存');
      navigate(`/teacher/${teacher.id}`);
    },
    onError: (error) => message.error(getApiErrorMessage(error)),
  });

  if (!user) return <Result status="403" title="请先登录" subTitle="登录后可以编辑教师资料。" />;
  if (teacherQuery.isLoading) return <Spin fullscreen description="加载教师信息" />;
  if (!teacherQuery.data) return <Result status="404" title="教师不存在或无法访问" />;

  const teacher = teacherQuery.data;
  const isAdmin = user.role === 'Admin';
  const infoDisabled = teacher.info_locked && !isAdmin;
  const imageDisabled = teacher.image_locked && !isAdmin;

  return (
    <div>
      <Seo title={`编辑教师信息 - ${teacher.name || ''}`} noindex />
      <PageTitle
        title="编辑教师信息"
        subtitle={
          <>
            教师：<Link to={`/teacher/${teacher.id}`}>{teacher.name}</Link>
          </>
        }
      />
      {(infoDisabled || imageDisabled) && (
        <Alert
          className="section-card"
          type="warning"
          showIcon
          title="部分信息已被管理员锁定"
          description="锁定项需要管理员解锁后才能修改。"
        />
      )}
      <Card className="section-card">
        <Form<TeacherUpdate>
          layout="vertical"
          initialValues={{
            description: teacher.description || '',
            homepage: teacher.homepage || '',
            research_interest: teacher.research_interest || '',
            office_phone: teacher.office_phone || '',
            info_locked: teacher.info_locked,
            image_locked: teacher.image_locked,
          }}
          onFinish={(values) => updateMutation.mutate(values)}
        >
          <Form.Item label="教师头像">
            <Upload
              accept="image/*"
              maxCount={1}
              disabled={imageDisabled}
              beforeUpload={(file) => {
                setAvatarFile(file);
                return false;
              }}
              onRemove={() => setAvatarFile(null)}
              fileList={
                avatarFile
                  ? ([{ uid: 'avatar', name: avatarFile.name, status: 'done' }] as UploadFile[])
                  : []
              }
            >
              <Button icon={<UploadOutlined />} disabled={imageDisabled}>
                选择图片
              </Button>
            </Upload>
          </Form.Item>
          <Form.Item name="homepage" label="教师主页">
            <Input disabled={infoDisabled} placeholder="https://..." />
          </Form.Item>
          <Form.Item name="research_interest" label="研究方向">
            <Input disabled={infoDisabled} />
          </Form.Item>
          <Form.Item name="description" label="教师简介">
            <Input.TextArea disabled={infoDisabled} autoSize={{ minRows: 4, maxRows: 10 }} />
          </Form.Item>
          {isAdmin && (
            <Space size={24} wrap>
              <Form.Item name="info_locked" label="锁定教师信息" valuePropName="checked">
                <Switch />
              </Form.Item>
              <Form.Item name="image_locked" label="锁定教师照片" valuePropName="checked">
                <Switch />
              </Form.Item>
            </Space>
          )}
          <Button type="primary" htmlType="submit" loading={updateMutation.isPending}>
            保存教师信息
          </Button>
        </Form>
      </Card>
      <Card className="section-card" title="修改记录">
        <Table<TeacherHistoryResponse>
          size="small"
          rowKey="id"
          loading={historyQuery.isLoading}
          dataSource={historyQuery.data || []}
          pagination={false}
          locale={{ emptyText: '暂无修改记录' }}
          columns={[
            { title: '时间', dataIndex: 'update_time', render: (value) => formatDateTime(value) },
            { title: '操作人', dataIndex: 'author', render: (value) => (value ? `用户 #${value}` : '-') },
            { title: '主页', dataIndex: 'homepage', render: (value) => value || '-' },
            { title: '研究方向', dataIndex: 'research_interest', render: (value) => value || '-' },
          ]}
          scroll={{ x: 600 }}
        />
      </Card>
    </div>
  );
}

