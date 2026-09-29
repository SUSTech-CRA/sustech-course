import { CommentOutlined, DeleteOutlined, DownOutlined, LinkOutlined, SendOutlined } from '@ant-design/icons';
import { Button, Form, Input, Popconfirm, Space, Typography, App as AntApp } from 'antd';
import { useEffect, useState } from 'react';

import { getApiErrorMessage } from '../../api/client';
import { useAuthStore } from '../../stores/authStore';
import { smartTime } from '../../utils/format';
import { HTMLContent } from '../common/HTMLContent';
import { ItemList } from '../common/ItemList';
import { UserAvatar } from '../common/UserAvatar';
import { UserLink } from '../common/UserLink';
import { useCommentMutation, useReviewComments } from '../../hooks/useReview';

interface ReviewCommentsProps {
  reviewId: number;
  count: number;
}

export function ReviewComments({ reviewId, count }: ReviewCommentsProps) {
  // Comments always start collapsed; the only auto-open exception is a direct #comment-{id} permalink.
  const [open, setOpen] = useState(() => window.location.hash.startsWith('#comment-'));
  const [form] = Form.useForm<{ content: string }>();
  const { message } = AntApp.useApp();
  const user = useAuthStore((state) => state.user);
  const commentsQuery = useReviewComments(reviewId, open);
  const commentMutations = useCommentMutation(reviewId);

  const submit = async (values: { content: string }) => {
    try {
      await commentMutations.add.mutateAsync(values.content);
      form.resetFields();
      message.success('评论已发布');
    } catch (error) {
      message.error(getApiErrorMessage(error));
    }
  };

  const remove = async (commentId: number) => {
    try {
      await commentMutations.remove.mutateAsync(commentId);
      message.success('评论已删除');
    } catch (error) {
      message.error(getApiErrorMessage(error));
    }
  };

  const reply = (username?: string | null) => {
    if (!username) return;
    form.setFieldValue('content', `@${username} `);
  };

  const copyCommentLink = async (commentId: number) => {
    const url = `${window.location.origin}${window.location.pathname}#comment-${commentId}`;
    await navigator.clipboard.writeText(url);
    message.success('评论链接已复制');
  };

  useEffect(() => {
    if (!open || !window.location.hash.startsWith('#comment-')) return;
    const timer = window.setTimeout(() => {
      document.getElementById(window.location.hash.slice(1))?.scrollIntoView({
        behavior: 'smooth',
        block: 'center',
      });
    }, 120);
    return () => window.clearTimeout(timer);
  }, [open, commentsQuery.data]);

  return (
    <div className="review-comments">
      <Button type="link" size="small" icon={<CommentOutlined />} onClick={() => setOpen(!open)}>
        {open ? '收起评论' : `评论 ${count}`}
        <DownOutlined className={`comment-toggle-icon${open ? ' comment-toggle-icon-open' : ''}`} />
      </Button>
      {open && (
        <div className="comment-panel">
          <ItemList
            size="small"
            loading={commentsQuery.isLoading}
            dataSource={commentsQuery.data || []}
            emptyText="还没有评论"
            rowKey={(comment) => comment.id}
            renderItem={(comment) => {
              const canDelete = Boolean(user && (user.role === 'Admin' || user.id === comment.author_id));
              return (
                <div className="comment-item" id={`comment-${comment.id}`}>
                  <UserAvatar size={28} src={comment.author?.avatar} name={comment.author?.username} />
                    <div className="comment-item-main">
                      <Space size={8} wrap className="comment-item-title">
                        <UserLink user={comment.author} />
                        <Typography.Text type="secondary">{smartTime(comment.publish_time)}</Typography.Text>
                      </Space>
                      <HTMLContent html={comment.content} />
                      <Space size={4} wrap className="comment-item-actions">
                        {user && comment.author?.username ? (
                          <Button type="link" size="small" onClick={() => reply(comment.author?.username)}>
                            回复
                          </Button>
                        ) : null}
                        <Button
                          type="text"
                          size="small"
                          icon={<LinkOutlined />}
                          onClick={() => copyCommentLink(comment.id)}
                        />
                        {canDelete ? (
                          <Popconfirm
                            title="删除评论"
                            description="确定删除这条评论吗？"
                            onConfirm={() => remove(comment.id)}
                          >
                            <Button danger type="text" size="small" icon={<DeleteOutlined />} />
                          </Popconfirm>
                        ) : null}
                      </Space>
                    </div>
                </div>
              );
            }}
          />
          {user ? (
            <Form form={form} onFinish={submit} className="comment-form">
              <Form.Item name="content" rules={[{ required: true, message: '请输入评论内容' }]}>
                <Input.TextArea placeholder="写下你的评论" autoSize={{ minRows: 2, maxRows: 5 }} />
              </Form.Item>
              <Button
                type="primary"
                htmlType="submit"
                icon={<SendOutlined />}
                loading={commentMutations.add.isPending}
              >
                发布评论
              </Button>
            </Form>
          ) : (
            <Typography.Text type="secondary">登录后可以参与评论。</Typography.Text>
          )}
        </div>
      )}
    </div>
  );
}
