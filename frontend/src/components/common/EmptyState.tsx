import { Empty } from 'antd';

interface EmptyStateProps {
  description?: string;
}

export function EmptyState({ description = '暂时没有数据' }: EmptyStateProps) {
  return <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={description} />;
}

