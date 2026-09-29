import { Rate, Space, Typography } from 'antd';

interface StarRatingProps {
  value?: number | null;
  count?: number;
  showText?: boolean;
  /** 弱化数字样式（灰色小号），用于点评卡等星星为主、数字为辅的场景 */
  muted?: boolean;
  size?: 'small' | 'default';
}

function formatRate(value: number, muted: boolean) {
  // 单条点评分是整数，弱化展示时不带小数点；聚合均分保持一位小数
  return muted && Number.isInteger(value) ? String(value) : Number(value).toFixed(1);
}

export function StarRating({ value, count, showText = true, muted = false, size = 'default' }: StarRatingProps) {
  const normalized = value ? value / 2 : 0;
  return (
    <Space size={6} className={size === 'small' ? 'rating-small' : undefined}>
      <Rate allowHalf disabled value={normalized} />
      {showText && (
        <Typography.Text strong={!muted} className={muted ? 'rating-value rating-value-muted' : 'rating-value'}>
          {value ? formatRate(value, muted) : '暂无'}
        </Typography.Text>
      )}
      {typeof count === 'number' && (
        <Typography.Text type="secondary">({count} 人评价)</Typography.Text>
      )}
    </Space>
  );
}
