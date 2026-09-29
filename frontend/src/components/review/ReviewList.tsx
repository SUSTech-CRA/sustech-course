import { Skeleton } from 'antd';

import type { ReviewResponse } from '../../types';
import { EmptyState } from '../common/EmptyState';
import { ItemList } from '../common/ItemList';
import { ReviewCard } from './ReviewCard';

interface ReviewListProps {
  reviews?: ReviewResponse[];
  loading?: boolean;
  compact?: boolean;
}

export function ReviewList({ reviews = [], loading, compact }: ReviewListProps) {
  if (loading) {
    return (
      <div className="stack">
        {Array.from({ length: 3 }).map((_, index) => (
          <Skeleton key={index} active avatar paragraph={{ rows: 3 }} />
        ))}
      </div>
    );
  }

  if (!reviews.length) {
    return <EmptyState description="还没有点评" />;
  }

  return (
    <ItemList
      dataSource={reviews}
      rowKey={(review) => review.id}
      renderItem={(review) => <ReviewCard review={review} compact={compact} />}
    />
  );
}
