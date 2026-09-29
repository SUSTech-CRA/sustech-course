import { useQuery } from '@tanstack/react-query';
import { Alert, Card, Typography } from 'antd';

import { adminApi } from '../api/admin';
import { HTMLContent } from '../components/common/HTMLContent';
import { ItemList, ItemMeta } from '../components/common/ItemList';
import { PageTitle } from '../components/common/PageTitle';
import { Seo } from '../components/common/Seo';
import { useAuthStore } from '../stores/authStore';
import { formatDateTime } from '../utils/format';

export function AnnouncementsPage() {
  const user = useAuthStore((state) => state.user);
  const enabled = user?.role === 'Admin';
  const announcementsQuery = useQuery({
    queryKey: ['admin', 'announcements'],
    queryFn: adminApi.announcements,
    enabled,
  });

  return (
    <div>
      <Seo title="公告" description="NCES 评课社区站点公告。" />
      <PageTitle title="公告" subtitle="公告 API 当前由管理员接口提供。" />
      {!enabled && (
        <Alert
          className="section-card"
          type="info"
          showIcon
          title="当前后端公告列表需要管理员权限；公开公告接口可在后续阶段补齐。"
        />
      )}
      {enabled && (
        <Card className="section-card">
          <ItemList
            loading={announcementsQuery.isLoading}
            dataSource={announcementsQuery.data || []}
            rowKey={(item) => item.id}
            renderItem={(item) => (
              <>
                <ItemMeta
                  title={item.title}
                  description={<Typography.Text type="secondary">{formatDateTime(item.update_time)}</Typography.Text>}
                />
                <HTMLContent html={item.content} />
              </>
            )}
          />
        </Card>
      )}
    </div>
  );
}

