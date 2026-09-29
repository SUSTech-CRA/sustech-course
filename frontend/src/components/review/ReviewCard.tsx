import {
  DeleteOutlined,
  EditOutlined,
  EyeInvisibleOutlined,
  EyeOutlined,
  LikeFilled,
  LikeOutlined,
  LockOutlined,
  LinkOutlined,
  StopOutlined,
} from '@ant-design/icons';
import { App as AntApp, Button, Card, Popconfirm, Space, Tag, Tooltip, Typography } from 'antd';
import { Link } from 'react-router-dom';

import { getApiErrorMessage } from '../../api/client';
import { useReviewMutations } from '../../hooks/useReview';
import { useAuthStore } from '../../stores/authStore';
import type { ReviewResponse } from '../../types';
import { smartTime } from '../../utils/format';
import { canEditReview, isAdmin, reviewVisibilityTags } from '../../utils/visibility';
import { HTMLContent } from '../common/HTMLContent';
import { SearchHighlight } from '../common/SearchHighlight';
import { StarRating } from '../common/StarRating';
import { UserAvatar } from '../common/UserAvatar';
import { UserLink } from '../common/UserLink';
import { ReviewComments } from './ReviewComments';

interface ReviewCardProps {
  review: ReviewResponse;
  compact?: boolean;
}

function visibilityTagTone(tag: string) {
  if (tag === '已屏蔽' || tag === '已隐藏') return 'danger';
  if (tag === '仅学生可见') return 'secure';
  return 'identity';
}

export function ReviewCard({ review, compact }: ReviewCardProps) {
  const { message } = AntApp.useApp();
  const user = useAuthStore((state) => state.user);
  const { upvote, remove, setHidden, setBlocked } = useReviewMutations();
  const visibilityTags = reviewVisibilityTags(review);
  const course = review.course;
  const metrics = [
    { label: '难度', value: review.difficulty_display },
    { label: '作业', value: review.homework_display },
    { label: '给分', value: review.grading_display },
    { label: '收获', value: review.gain_display },
  ].filter((metric) => metric.value);
  const isUpdated = Boolean(
    review.publish_time &&
      review.update_time &&
      review.publish_time !== review.update_time,
  );
  const reviewUrl = course
    ? `${window.location.origin}/course/${course.id}#review-${review.id}`
    : `${window.location.origin}/reviews/${review.id}`;

  const canManage = canEditReview(review, user);
  const isSelfAuthor = Boolean(user && review.author && user.id === review.author.id);
  const admin = isAdmin(user);

  const toggleUpvote = async () => {
    if (!user) {
      message.info('请先登录再点赞');
      return;
    }
    try {
      await upvote.mutateAsync({ reviewId: review.id, enabled: !review.is_upvoted });
    } catch (error) {
      message.error(getApiErrorMessage(error));
    }
  };

  const deleteReview = async () => {
    try {
      await remove.mutateAsync(review.id);
      message.success('点评已删除');
    } catch (error) {
      message.error(getApiErrorMessage(error));
    }
  };

  const toggleHidden = async () => {
    try {
      await setHidden.mutateAsync({ reviewId: review.id, hidden: !review.is_hidden });
      message.success(review.is_hidden ? '点评已取消隐藏' : '点评已隐藏，仅自己和管理员可见');
    } catch (error) {
      message.error(getApiErrorMessage(error));
    }
  };

  const toggleBlocked = async () => {
    try {
      await setBlocked.mutateAsync({ reviewId: review.id, blocked: !review.is_blocked });
      message.success(review.is_blocked ? '点评已解除屏蔽' : '点评已屏蔽');
    } catch (error) {
      message.error(getApiErrorMessage(error));
    }
  };

  return (
    <Card className="review-card" size="small" id={`review-${review.id}`}>
      <div className="review-header">
        <Space align="start" size={10}>
          <UserAvatar size={40} src={review.author?.avatar} name={review.author?.username} />
          <div>
            <Space size={6} wrap>
              <UserLink user={review.author} anonymous={review.is_anonymous} />
              <Typography.Text type="secondary">
                {isUpdated ? '更新了点评' : '点评了'}
              </Typography.Text>
              {course ? (
                <Link to={reviewUrl} style={{ textDecoration: 'underline' }}>
                  {course.name}
                </Link>
              ) : (
                '未知课程'
              )}
              {course?.teacher_names && (
                <Typography.Text type="secondary">({course.teacher_names})</Typography.Text>
              )}
            </Space>
            <div className="muted-line">
              <span>发布于 {smartTime(review.publish_time)}</span>
              {isUpdated && <span>更新于 {smartTime(review.update_time)}</span>}
            </div>
          </div>
        </Space>
        <StarRating value={review.rate} muted size="small" />
      </div>

      <div className="review-tags">
        <Tag color="blue" className="review-term-tag">
          {review.term_display || review.term}
        </Tag>
        <span className="review-metric-tags">
          {metrics.map((metric) => (
            <Tag key={metric.label} className="review-metric-tag">
              <span className="review-metric-label">{metric.label}</span>
              <span className="review-metric-value">{metric.value}</span>
            </Tag>
          ))}
        </span>
        {visibilityTags.length > 0 && (
          <span className="review-status-tags">
            {visibilityTags.map((tag) => (
              <Tag key={tag} className={`review-status-tag review-status-${visibilityTagTone(tag)}`}>
                {tag === '仅学生可见' && <LockOutlined />} {tag}
              </Tag>
            ))}
          </span>
        )}
      </div>

      {compact && review.content_snippet ? (
        // 搜索结果：展示命中位置的高亮摘要（服务端已裁剪+转义），替代开头截断预览
        <div className="review-search-snippet">
          <SearchHighlight html={review.content_snippet} />
          <Typography.Link href={reviewUrl} className="review-search-snippet-link">
            查看完整点评{review.comment_count ? `（${review.comment_count} 条评论）` : ''}
          </Typography.Link>
        </div>
      ) : (
        <HTMLContent
          html={review.content}
          previewChars={compact ? 100 : undefined}
          expandedExtra={
            compact ? (
              <Typography.Link href={reviewUrl}>
                在课程页查看{review.comment_count ? `（${review.comment_count} 条评论）` : ''}
              </Typography.Link>
            ) : undefined
          }
        />
      )}

      <div className="review-actions">
        <Space size={4}>
          <Tooltip title={review.is_upvoted ? '取消点赞' : '点赞'}>
            <Button
              type="text"
              size="small"
              className="mono-text"
              icon={review.is_upvoted ? <LikeFilled /> : <LikeOutlined />}
              loading={upvote.isPending}
              onClick={toggleUpvote}
            >
              {review.upvote_count}
            </Button>
          </Tooltip>
          <Button
            type="link"
            size="small"
            icon={<LinkOutlined />}
            onClick={async () => {
              await navigator.clipboard.writeText(reviewUrl);
              message.success('点评链接已复制');
            }}
          >
            复制链接
          </Button>
          {canManage && (
            <Button
              type="link"
              size="small"
              icon={<EditOutlined />}
              href={`/reviews/${review.id}/edit`}
            >
              编辑
            </Button>
          )}
          {canManage && (
            <Popconfirm
              title="删除点评"
              description="删除后无法恢复，确定删除这条点评吗？"
              okText="删除"
              okButtonProps={{ danger: true }}
              onConfirm={deleteReview}
            >
              <Button danger type="link" size="small" icon={<DeleteOutlined />} loading={remove.isPending}>
                删除
              </Button>
            </Popconfirm>
          )}
          {(isSelfAuthor || admin) && (
            <Button
              type="link"
              size="small"
              icon={review.is_hidden ? <EyeOutlined /> : <EyeInvisibleOutlined />}
              loading={setHidden.isPending}
              onClick={toggleHidden}
            >
              {review.is_hidden ? '取消隐藏' : '隐藏'}
            </Button>
          )}
          {admin && (
            <Popconfirm
              title={review.is_blocked ? '解除屏蔽' : '屏蔽点评'}
              description={
                review.is_blocked
                  ? '确定解除屏蔽这条点评吗？'
                  : '屏蔽后仅作者和管理员可见，确定屏蔽这条点评吗？'
              }
              okText={review.is_blocked ? '解除屏蔽' : '屏蔽'}
              okButtonProps={{ danger: !review.is_blocked }}
              onConfirm={toggleBlocked}
            >
              <Button danger type="link" size="small" icon={<StopOutlined />} loading={setBlocked.isPending}>
                {review.is_blocked ? '解除屏蔽' : '屏蔽'}
              </Button>
            </Popconfirm>
          )}
        </Space>
      </div>

      {!compact && <ReviewComments reviewId={review.id} count={review.comment_count} />}
    </Card>
  );
}
