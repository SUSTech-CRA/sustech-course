import { TeamOutlined, UserOutlined } from '@ant-design/icons';
import { useQuery } from '@tanstack/react-query';
import { Card, Pagination, Result, Skeleton, Space, Typography } from 'antd';
import { useEffect, useRef } from 'react';
import { Link, useParams, useSearchParams } from 'react-router-dom';

import { usersApi } from '../api/users';
import { CourseList } from '../components/course/CourseList';
import { EmptyState } from '../components/common/EmptyState';
import { ItemList } from '../components/common/ItemList';
import { PageTitle } from '../components/common/PageTitle';
import { Seo } from '../components/common/Seo';
import { UserAvatar } from '../components/common/UserAvatar';
import type { UserBrief } from '../types';

type UserFollowListKind = 'followers' | 'followings' | 'following-courses' | 'joined-courses';

const pageMeta: Record<UserFollowListKind, { title: string; subtitle: string }> = {
  followers: { title: '粉丝', subtitle: '关注这位用户的人' },
  followings: { title: '关注', subtitle: '这位用户关注的人' },
  'following-courses': { title: '关注课程', subtitle: '这位用户关注的课程' },
  'joined-courses': { title: '学过的课程', subtitle: '这位用户学过的课程' },
};

interface UserFollowListPageProps {
  kind: UserFollowListKind;
}

function UserList({ users = [], loading }: { users?: UserBrief[]; loading?: boolean }) {
  if (loading) {
    return (
      <div className="stack">
        {Array.from({ length: 5 }).map((_, index) => (
          <Skeleton key={index} active avatar paragraph={{ rows: 1 }} />
        ))}
      </div>
    );
  }
  if (!users.length) return <EmptyState description="这里暂时还没有用户" />;

  return (
    <ItemList
      dataSource={users}
      rowKey={(user) => user.id}
      renderItem={(user) => (
        <Link to={`/user/${user.id}`} className="user-list-row">
          <UserAvatar size={42} src={user.avatar} name={user.username} />
          <span>
            <Typography.Text strong>{user.username}</Typography.Text>
            {user.identity && (
              <Typography.Text type="secondary" className="user-list-identity">
                {user.identity}
              </Typography.Text>
            )}
          </span>
        </Link>
      )}
    />
  );
}

export function UserFollowListPage({ kind }: UserFollowListPageProps) {
  const { id } = useParams();
  const [params, setParams] = useSearchParams();
  const page = Number(params.get('page') || 1);
  const listRef = useRef<HTMLDivElement>(null);
  const didMountRef = useRef(false);
  const profileQuery = useQuery({
    queryKey: ['user', id],
    queryFn: () => usersApi.profile(id as string),
    enabled: Boolean(id),
  });
  const isCourseList = kind === 'following-courses' || kind === 'joined-courses';
  const userListQuery = useQuery({
    queryKey: ['user', id, kind, page],
    queryFn: () =>
      kind === 'followers'
        ? usersApi.followers(id as string, { page, per_page: 30 })
        : usersApi.followings(id as string, { page, per_page: 30 }),
    enabled: Boolean(id && !isCourseList),
    placeholderData: (previous) => previous,
  });
  const courseListQuery = useQuery({
    queryKey: ['user', id, kind, page],
    queryFn: () =>
      kind === 'joined-courses'
        ? usersApi.joinedCourses(id as string, { page, per_page: 20 })
        : usersApi.followingCourses(id as string, { page, per_page: 20 }),
    enabled: Boolean(id && isCourseList),
    placeholderData: (previous) => previous,
  });

  const activeQuery = isCourseList ? courseListQuery : userListQuery;
  const profile = profileQuery.data;
  const meta = pageMeta[kind];

  useEffect(() => {
    if (!didMountRef.current) {
      didMountRef.current = true;
      return;
    }
    listRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, [page]);

  if (profileQuery.isError || activeQuery.isError) {
    return <Result status="404" title="列表不存在或无法访问" />;
  }

  return (
    <div>
      <Seo title={profile ? `${profile.username} 的${meta.title}` : meta.title} noindex />
      <PageTitle
        title={
          <Space>
            {isCourseList ? <TeamOutlined /> : <UserOutlined />}
            {profile ? `${profile.username} 的${meta.title}` : meta.title}
          </Space>
        }
        subtitle={`${meta.subtitle} · 共 ${activeQuery.data?.total || 0} 项`}
      />
      <div ref={listRef}>
        <Card className="section-card">
          {isCourseList ? (
            <CourseList courses={courseListQuery.data?.items} loading={courseListQuery.isLoading} />
          ) : (
            <UserList users={userListQuery.data?.items} loading={userListQuery.isLoading} />
          )}
          <Pagination
            className="pager"
            current={activeQuery.data?.page || page}
            pageSize={activeQuery.data?.per_page || (isCourseList ? 20 : 30)}
            total={activeQuery.data?.total || 0}
            showSizeChanger={false}
            onChange={(nextPage) => setParams({ page: String(nextPage) })}
          />
        </Card>
      </div>
    </div>
  );
}
