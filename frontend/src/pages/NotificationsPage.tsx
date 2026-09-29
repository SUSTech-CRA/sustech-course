import { CheckOutlined } from '@ant-design/icons';
import { Button, Card, Result, Space, Typography } from 'antd';
import { useEffect, useRef, useState } from 'react';

import { PageTitle } from '../components/common/PageTitle';
import { HTMLContent } from '../components/common/HTMLContent';
import { ItemList } from '../components/common/ItemList';
import { Seo } from '../components/common/Seo';
import { useNotifications, useReadNotificationsMutation } from '../hooks/useNotification';
import { useAuthStore } from '../stores/authStore';
import { smartTime } from '../utils/format';

export function NotificationsPage() {
  const [page] = useState(1);
  const user = useAuthStore((state) => state.user);
  const notificationsQuery = useNotifications(page, 30);
  const readMutation = useReadNotificationsMutation();
  const markedReadRef = useRef(false);

  useEffect(() => {
    if (!user?.unread_notification_count || markedReadRef.current) return;
    markedReadRef.current = true;
    readMutation.mutate();
  }, [readMutation, user?.unread_notification_count]);

  if (!user) return <Result status="403" title="请先登录" />;

  return (
    <div>
      <Seo title="通知" noindex />
      <PageTitle
        title="通知"
        subtitle="查看点赞、评论、课程相关消息。"
        extra={
          <Button
            icon={<CheckOutlined />}
            onClick={() => readMutation.mutate()}
            loading={readMutation.isPending}
          >
            全部已读
          </Button>
        }
      />
      <Card className="section-card">
        <ItemList
          loading={notificationsQuery.isLoading}
          dataSource={notificationsQuery.data?.items || []}
          emptyText="暂无通知"
          rowKey={(item) => item.id}
          renderItem={(item) => (
            <Space orientation="vertical" size={2}>
              <HTMLContent
                html={item.display_text || item.operation}
                className="notification-text"
              />
              <Typography.Text type="secondary">{smartTime(item.time)}</Typography.Text>
            </Space>
          )}
        />
      </Card>
    </div>
  );
}
