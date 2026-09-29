import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { App as AntApp, Button, Card, Form, Input, Result, Typography } from 'antd';

import { adminApi } from '../../api/admin';
import { getApiErrorMessage } from '../../api/client';
import { ItemList, ItemMeta } from '../../components/common/ItemList';
import { PageTitle } from '../../components/common/PageTitle';
import { Seo } from '../../components/common/Seo';
import { HTMLContent } from '../../components/common/HTMLContent';
import { useAuthStore } from '../../stores/authStore';
import type { BannerCreate } from '../../types';
import { formatDateTime } from '../../utils/format';

export function BannerPage() {
  const user = useAuthStore((state) => state.user);
  const { message } = AntApp.useApp();
  const queryClient = useQueryClient();
  const bannersQuery = useQuery({
    queryKey: ['admin', 'banners'],
    queryFn: adminApi.banners,
    enabled: user?.role === 'Admin',
  });
  const createMutation = useMutation({
    mutationFn: (payload: BannerCreate) => adminApi.createBanner(payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin', 'banners'] });
      message.success('Banner 已创建');
    },
    onError: (error) => message.error(getApiErrorMessage(error)),
  });

  if (user?.role !== 'Admin') return <Result status="403" title="需要管理员权限" />;

  return (
    <div>
      <Seo title="Banner 管理" noindex />
      <PageTitle title="Banner 管理" subtitle="基础管理页面，供后续完善上传和富文本流程。" />
      <Card className="section-card" title="创建 Banner">
        <Form<BannerCreate> layout="vertical" onFinish={(values) => createMutation.mutate(values)}>
          <Form.Item name="desktop" label="桌面端 HTML">
            <Input.TextArea autoSize={{ minRows: 3 }} />
          </Form.Item>
          <Form.Item name="mobile" label="移动端 HTML">
            <Input.TextArea autoSize={{ minRows: 3 }} />
          </Form.Item>
          <Button type="primary" htmlType="submit" loading={createMutation.isPending}>
            创建
          </Button>
        </Form>
      </Card>
      <Card className="section-card" title="已有 Banner">
        <ItemList
          loading={bannersQuery.isLoading}
          dataSource={bannersQuery.data || []}
          rowKey={(item) => item.id}
          renderItem={(item) => (
            <>
              <ItemMeta
                title={<Typography.Text>#{item.id}</Typography.Text>}
                description={formatDateTime(item.publish_time)}
              />
              <HTMLContent html={item.desktop || item.mobile} />
            </>
          )}
        />
      </Card>
    </div>
  );
}

