import { FireOutlined, InfoCircleOutlined, ReadOutlined } from '@ant-design/icons';
import { Card, Col, Pagination, Row, Segmented, Space, Statistic, Typography } from 'antd';
import { useEffect, useRef } from 'react';
import { Link, useLocation, useSearchParams } from 'react-router-dom';

import { ReviewFilter } from '../components/review/ReviewFilter';
import { ReviewList } from '../components/review/ReviewList';
import { PageTitle } from '../components/common/PageTitle';
import { Seo } from '../components/common/Seo';
import { SentryFeedbackButton } from '../components/common/SentryFeedbackButton';
import { useAuthStore } from '../stores/authStore';
import { useReviews } from '../hooks/useReview';
import { useSiteStats } from '../hooks/useStats';
import type { ReviewFeedFilter, ReviewSortBy } from '../types';

export function HomePage() {
  const location = useLocation();
  const [params, setParams] = useSearchParams();
  const user = useAuthStore((state) => state.user);
  // 兼容老版 /follow_reviews?follow_type=user 链接
  const legacyFollowType = params.get('follow_type');
  const defaultFilter: ReviewFeedFilter =
    location.pathname.includes('follow_reviews') && user
      ? legacyFollowType === 'user'
        ? 'following_users'
        : 'following'
      : 'latest';
  const page = Math.max(Number(params.get('page') || 1), 1);
  const sortBy = (params.get('sort_by') || 'updatetime_desc') as ReviewSortBy;
  const filter = (params.get('filter') || defaultFilter) as ReviewFeedFilter;
  const reviewsQuery = useReviews({ page, per_page: 12, sort_by: sortBy, filter });
  const statsQuery = useSiteStats();
  const listRef = useRef<HTMLDivElement>(null);
  const didMountRef = useRef(false);

  useEffect(() => {
    if (!didMountRef.current) {
      didMountRef.current = true;
      return;
    }
    listRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, [page, sortBy, filter]);

  const updateParams = (updates: Record<string, string | number | undefined>) => {
    const next = new URLSearchParams(params);
    Object.entries(updates).forEach(([key, value]) => {
      if (value === undefined || value === '' || value === 'latest') {
        next.delete(key);
      } else {
        next.set(key, String(value));
      }
    });
    setParams(next);
  };

  const changeFilter = (value: string | number) => {
    updateParams({ filter: value, page: 1 });
  };

  const siteOrigin = window.location.origin;
  const homeJsonLd = {
    '@context': 'https://schema.org',
    '@type': 'WebSite',
    name: 'NCES 评课社区',
    url: `${siteOrigin}/`,
    potentialAction: {
      '@type': 'SearchAction',
      target: `${siteOrigin}/search?q={search_term_string}&type=all`,
      'query-input': 'required name=search_term_string',
    },
  };

  return (
    <>
      <Seo
        title="全站最新点评"
        description="浏览南方科技大学（SUSTech）全站最新课程点评，按时间或推荐排序查看同学们的真实课程体验。"
        jsonLd={homeJsonLd}
      />
      <Row gutter={[20, 20]}>
      <Col xs={24} lg={17}>
        <PageTitle
          title="全站最新点评"
          subtitle=""
          extra={
            <Segmented
              value={filter}
              onChange={changeFilter}
              options={[
                { label: '全站', value: 'latest' },
                { label: '关注的课程', value: 'following', disabled: !user },
                { label: '关注的人', value: 'following_users', disabled: !user },
              ]}
            />
          }
        />
        <div ref={listRef}>
          <Card className="section-card">
            <ReviewFilter
              sortBy={sortBy}
              onSortChange={(value) => updateParams({ sort_by: value, page: 1 })}
            />
            <ReviewList reviews={reviewsQuery.data?.items} loading={reviewsQuery.isLoading} compact />
            <Pagination
              className="pager"
              current={reviewsQuery.data?.page || page}
              pageSize={reviewsQuery.data?.per_page || 12}
              total={reviewsQuery.data?.total || 0}
              showSizeChanger={false}
              onChange={(nextPage) => updateParams({ page: nextPage })}
            />
          </Card>
        </div>
      </Col>
      <Col xs={24} lg={7}>
        <div className="side-stack">
          <Card className="section-card" size="small" title="站点概览">
            <Row gutter={[12, 12]}>
              <Col span={12}>
                <Statistic title="课程" value={statsQuery.data?.course_count || 0} />
              </Col>
              <Col span={12}>
                <Statistic title="点评" value={statsQuery.data?.review_count || 0} />
              </Col>
              <Col span={12}>
                <Statistic title="用户" value={statsQuery.data?.user_count || 0} />
              </Col>
              <Col span={12}>
                <Statistic title="教师" value={statsQuery.data?.teacher_count || 0} />
              </Col>
            </Row>
          </Card>
          <Card className="section-card" size="small" title="快速入口">
            <Space orientation="vertical">
              <Link to="/courses">
                <ReadOutlined /> 浏览课程列表
              </Link>
              <Link to="/rankings">
                <FireOutlined /> 查看课程排行榜
              </Link>
              <Link to="/stats">
                <InfoCircleOutlined /> 站点统计
              </Link>
              <Link to="/about">
                <InfoCircleOutlined /> 关于本站
              </Link>
              <SentryFeedbackButton source="home_quick_entry" />
              <Typography.Text type="secondary">
                如果遇到任何问题，请点击上方的反馈按钮提交反馈（按钮可能会被Adblock拦截），或邮件 service@ncesnext.com 联系管理员。
              </Typography.Text>
            </Space>
          </Card>
        </div>
      </Col>
      </Row>
    </>
  );
}
