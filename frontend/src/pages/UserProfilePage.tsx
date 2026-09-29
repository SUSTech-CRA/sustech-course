import { CheckOutlined, HeartFilled, HeartOutlined, LinkOutlined } from '@ant-design/icons';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { App as AntApp, Button, Card, Pagination, Result, Space, Spin, Tabs, Tag, Typography } from 'antd';
import { useEffect, useRef, useState } from 'react';
import { Link, useParams, useSearchParams } from 'react-router-dom';

import { getApiErrorMessage } from '../api/client';
import { usersApi } from '../api/users';
import { CourseList } from '../components/course/CourseList';
import { HTMLContent } from '../components/common/HTMLContent';
import { Seo } from '../components/common/Seo';
import { UserAvatar } from '../components/common/UserAvatar';
import { ReviewList } from '../components/review/ReviewList';
import { useAuthStore } from '../stores/authStore';
import { formatDateTime, stripHtmlForSummary } from '../utils/format';

export function UserProfilePage() {
  const { id } = useParams();
  const [params, setParams] = useSearchParams();
  const { message } = AntApp.useApp();
  const queryClient = useQueryClient();
  const viewer = useAuthStore((state) => state.user);
  const reviewPage = Math.max(Number(params.get('review_page') || 1), 1);
  const coursePage = Math.max(Number(params.get('course_page') || 1), 1);
  const [activeTab, setActiveTab] = useState('reviews');
  const [followHover, setFollowHover] = useState(false);
  const [followPending, setFollowPending] = useState(false);
  const listsRef = useRef<HTMLDivElement>(null);
  const didMountRef = useRef(false);
  const profileQuery = useQuery({
    queryKey: ['user', id],
    queryFn: () => usersApi.profile(id as string),
    enabled: Boolean(id),
  });
  const reviewsQuery = useQuery({
    queryKey: ['user', id, 'reviews', reviewPage],
    queryFn: () => usersApi.reviews(id as string, { page: reviewPage, per_page: 10 }),
    enabled: Boolean(id),
    placeholderData: (previous) => previous,
  });
  // is_following_hidden 用户（非本人视角）的关注列表接口会 404，等 profile 拿到可见性再查
  const canViewFollowing = profileQuery.data ? profileQuery.data.following_count !== null : false;
  const coursesQuery = useQuery({
    queryKey: ['user', id, 'following-courses', coursePage],
    queryFn: () => usersApi.followingCourses(id as string, { page: coursePage, per_page: 10 }),
    enabled: Boolean(id) && canViewFollowing,
    placeholderData: (previous) => previous,
  });

  useEffect(() => {
    if (!didMountRef.current) {
      didMountRef.current = true;
      return;
    }
    listsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, [reviewPage, coursePage]);

  if (profileQuery.isLoading) return <Spin fullscreen description="加载用户主页" />;
  if (!profileQuery.data) return <Result status="404" title="用户不存在或无法访问" />;

  const profile = profileQuery.data;
  const isSelf = viewer?.id === profile.id;
  const homepage = profile.homepage && profile.homepage !== 'http://' ? profile.homepage : null;

  const updateListPage = (key: 'review_page' | 'course_page', page: number) => {
    const next = new URLSearchParams(params);
    if (page <= 1) next.delete(key);
    else next.set(key, String(page));
    setParams(next);
  };

  const toggleFollow = async () => {
    if (!viewer) {
      message.info('请先登录');
      return;
    }
    setFollowPending(true);
    try {
      await usersApi.setFollow(profile.id, !profile.is_following);
      message.success(profile.is_following ? '已取消关注' : '已关注用户');
      queryClient.invalidateQueries({ queryKey: ['user', id] });
    } catch (error) {
      message.error(getApiErrorMessage(error));
    } finally {
      setFollowPending(false);
    }
  };

  const openListTab = (key: string) => {
    setActiveTab(key);
    listsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  const seoDescription =
    stripHtmlForSummary(profile.description, 140) || `${profile.username} 在 NCES 评课社区的个人主页。`;

  const followButton =
    !isSelf &&
    (profile.is_following ? (
      <Button
        block
        icon={followHover ? <HeartOutlined /> : <CheckOutlined />}
        danger={followHover}
        loading={followPending}
        onMouseEnter={() => setFollowHover(true)}
        onMouseLeave={() => setFollowHover(false)}
        onClick={toggleFollow}
      >
        {followHover ? '取消关注' : '已关注'}
      </Button>
    ) : (
      <Button block type="primary" icon={<HeartFilled />} loading={followPending} onClick={toggleFollow}>
        关注
      </Button>
    ));

  const sideColumn = (
    <>
      <Card className="section-card profile-side-card">
        <div className="profile-side-head">
          <UserAvatar size={96} src={profile.avatar} name={profile.username} />
          <Typography.Title level={4} className="profile-side-name">
            {profile.username}
          </Typography.Title>
          <Space size={4} wrap className="profile-side-badges">
            {profile.identity === 'Teacher' && <Tag color="green">老师</Tag>}
            {profile.identity === 'Student' && <Tag color="blue">学生</Tag>}
            {profile.role === 'Admin' && <Tag color="gold">管理员</Tag>}
          </Space>
        </div>
        {profile.description && (
          <div className="profile-side-description">
            <HTMLContent html={profile.description} />
          </div>
        )}
        <ul className="profile-side-meta">
          {homepage && (
            <li>
              <LinkOutlined />{' '}
              <a href={homepage} target="_blank" rel="noopener noreferrer">
                {homepage}
              </a>
            </li>
          )}
          <li>注册于 {formatDateTime(profile.register_time)}</li>
          <li>
            主页访问 <span className="mono-font">{profile.access_count}</span> 次
          </li>
          {isSelf && profile.email && <li>{profile.email}</li>}
        </ul>
        {followButton}
      </Card>
      {canViewFollowing && (
        <Card className="section-card profile-side-card">
          <ul className="profile-side-stats">
            <li>
              关注了{' '}
              <Link to={`/user/${profile.id}/followings`} className="mono-font">
                {profile.following_count}
              </Link>{' '}
              人
            </li>
            <li>
              被{' '}
              <Link to={`/user/${profile.id}/followers`} className="mono-font">
                {profile.follower_count}
              </Link>{' '}
              人关注
            </li>
            <li>
              关注了{' '}
              <Link to={`/user/${profile.id}/follow_course`} className="mono-font">
                {coursesQuery.data?.total ?? '-'}
              </Link>{' '}
              门课程
            </li>
            <li>
              点评了{' '}
              <a
                className="mono-font"
                onClick={(event) => {
                  event.preventDefault();
                  openListTab('reviews');
                }}
              >
                {reviewsQuery.data?.total ?? '-'}
              </a>{' '}
              门课程
            </li>
          </ul>
        </Card>
      )}
    </>
  );

  return (
    <div>
      <Seo title={`${profile.username} 的主页`} description={seoDescription} />
      <div className="profile-layout">
        <div className="profile-layout-side">{sideColumn}</div>
        <div className="profile-layout-main" ref={listsRef}>
          <Card className="section-card">
            <Tabs
              activeKey={activeTab}
              onChange={setActiveTab}
              items={[
                {
                  key: 'reviews',
                  label: `点评 ${reviewsQuery.data?.total ?? 0}`,
                  children: (
                    <>
                      <ReviewList reviews={reviewsQuery.data?.items} loading={reviewsQuery.isLoading} />
                      <Pagination
                        className="pager"
                        current={reviewsQuery.data?.page || reviewPage}
                        pageSize={reviewsQuery.data?.per_page || 10}
                        total={reviewsQuery.data?.total || 0}
                        showSizeChanger={false}
                        onChange={(nextPage) => updateListPage('review_page', nextPage)}
                      />
                    </>
                  ),
                },
                ...(canViewFollowing
                  ? [
                      {
                        key: 'courses',
                        label: `关注的课程 ${coursesQuery.data?.total ?? 0}`,
                        children: (
                          <>
                            <CourseList courses={coursesQuery.data?.items} loading={coursesQuery.isLoading} />
                            <Pagination
                              className="pager"
                              current={coursesQuery.data?.page || coursePage}
                              pageSize={coursesQuery.data?.per_page || 10}
                              total={coursesQuery.data?.total || 0}
                              showSizeChanger={false}
                              onChange={(nextPage) => updateListPage('course_page', nextPage)}
                            />
                          </>
                        ),
                      },
                    ]
                  : []),
              ]}
            />
          </Card>
        </div>
      </div>
    </div>
  );
}
