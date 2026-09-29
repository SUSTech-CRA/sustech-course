import { Select, Space, Typography } from 'antd';

import type { ReviewSortBy } from '../../types';
import { REVIEW_SORT_OPTIONS } from '../../utils/constants';

interface ReviewFilterProps {
  sortBy: ReviewSortBy;
  term?: string;
  rating?: number;
  termOptions?: string[];
  onSortChange: (value: ReviewSortBy) => void;
  onTermChange?: (value?: string) => void;
  onRatingChange?: (value?: number) => void;
}

export function ReviewFilter({
  sortBy,
  term,
  rating,
  termOptions = [],
  onSortChange,
  onTermChange,
  onRatingChange,
}: ReviewFilterProps) {
  return (
    <Space size={12} wrap className="toolbar">
      <Typography.Text strong>排序</Typography.Text>
      <Select
        value={sortBy}
        options={REVIEW_SORT_OPTIONS}
        onChange={onSortChange}
        className="select-md"
      />
      {onTermChange && (
        <>
          <Typography.Text strong>学期</Typography.Text>
          <Select
            allowClear
            placeholder="全部"
            value={term}
            options={termOptions.map((value) => ({ label: value, value }))}
            onChange={onTermChange}
            className="select-md"
          />
        </>
      )}
      {onRatingChange && (
        <>
          <Typography.Text strong>评分</Typography.Text>
          <Select
            allowClear
            placeholder="全部"
            value={rating}
            options={Array.from({ length: 10 }, (_, index) => 10 - index).map((value) => ({
              label: `${value} 分`,
              value,
            }))}
            onChange={onRatingChange}
            className="select-sm"
          />
        </>
      )}
    </Space>
  );
}

