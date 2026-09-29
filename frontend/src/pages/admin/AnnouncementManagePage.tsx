import { DeleteOutlined } from '@ant-design/icons';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { App as AntApp, Button, Card, Form, Input, Popconfirm, Result } from 'antd';

import { adminApi } from '../../api/admin';
import { getApiErrorMessage } from '../../api/client';
import { ItemList, ItemMeta } from '../../components/common/ItemList';
import { PageTitle } from '../../components/common/PageTitle';
import { Seo } from '../../components/common/Seo';
import { HTMLContent } from '../../components/common/HTMLContent';
import { useAuthStore } from '../../stores/authStore';
import type { AnnouncementCreate } from '../../types';

export function AnnouncementManagePage() {
  const user = useAuthStore((state) => state.user);
  const { message } = AntApp.useApp();
  const queryClient = useQueryClient();
  const announcementsQuery = useQuery({
    queryKey: ['admin', 'announcements'],
    queryFn: adminApi.announcements,
    enabled: user?.role === 'Admin',
  });
  const createMutation = useMutation({
    mutationFn: (payload: AnnouncementCreate) => adminApi.createAnnouncement(payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin', 'announcements'] });
      message.success('公告已创建');
    },
    onError: (error) => message.error(getApiErrorMessage(error)),
  });
  const deleteMutation = useMutation({
    mutationFn: (id: number) => adminApi.deleteAnnouncement(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin', 'announcements'] });
      message.success('公告已删除');
    },
    onError: (error) => message.error(getApiErrorMessage(error)),
  });

  if (user?.role !== 'Admin') return <Result status="403" title="需要管理员权限" />;

  return (
    <div>
      <Seo title="公告管理" noindex />
      <PageTitle title="公告管理" subtitle="创建、查看和删除公告。" />
      <Card className="section-card" title="创建公告">
        <Form<AnnouncementCreate> layout="vertical" onFinish={(values) => createMutation.mutate(values)}>
          <Form.Item name="title" label="标题" rules={[{ required: true }]}>
            <Input />
          </Form.Item>
          <Form.Item name="content" label="内容" rules={[{ required: true }]}>
            <Input.TextArea autoSize={{ minRows: 5 }} />
          </Form.Item>
          <Button type="primary" htmlType="submit" loading={createMutation.isPending}>
            创建
          </Button>
        </Form>
      </Card>
      <Card className="section-card" title="公告列表">
        <ItemList
          loading={announcementsQuery.isLoading}
          dataSource={announcementsQuery.data || []}
          rowKey={(item) => item.id}
          renderItem={(item) => (
            <>
              <ItemMeta title={item.title} description={<HTMLContent html={item.content} maxRows={3} />} />
              <div className="item-list-actions">
                <Popconfirm
                  title="删除公告"
                  description="确定删除这条公告吗？"
                  onConfirm={() => deleteMutation.mutate(item.id)}
                >
                  <Button danger type="text" icon={<DeleteOutlined />} />
                </Popconfirm>
              </div>
            </>
          )}
        />
      </Card>
    </div>
  );
}

