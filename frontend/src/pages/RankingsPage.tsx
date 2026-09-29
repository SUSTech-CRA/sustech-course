import { Card, Space, Table, Tag, Typography } from 'antd';
import type { TableProps } from 'antd';
import { Link } from 'react-router-dom';

import { PageTitle } from '../components/common/PageTitle';
import { Seo } from '../components/common/Seo';
import { UserAvatar } from '../components/common/UserAvatar';
import { useRankings } from '../hooks/useStats';
import type {
  CourseRankingItem,
  ReviewRankingItem,
  TeacherRankingItem,
  UserRankingItem,
} from '../types';

function rankText(index: number) {
  return <span className="mono-text">#{index + 1}</span>;
}

function scoreText(value?: number | null, digits = 1) {
  return <span className="mono-text">{typeof value === 'number' ? value.toFixed(digits) : '-'}</span>;
}

function countText(value?: number | null) {
  return <span className="mono-text">{value || 0}</span>;
}

const courseColumns: TableProps<CourseRankingItem>['columns'] = [
  { title: '#', width: 64, render: (_, __, index) => rankText(index) },
  {
    title: '课程',
    dataIndex: 'name',
    render: (name, course) => <Link to={`/course/${course.id}`}>{name}</Link>,
  },
  { title: '教师', dataIndex: 'teacher_names', responsive: ['md'] },
  {
    title: '课程号',
    dataIndex: 'course_code',
    render: (value) => value && <Tag className="mono-text">{value}</Tag>,
    responsive: ['lg'],
  },
  { title: '点评', dataIndex: 'review_count', render: countText },
  { title: '评分', dataIndex: 'rate_average', render: (value) => scoreText(value, 1) },
  {
    title: '归一化',
    dataIndex: 'normalized_rate',
    render: (value) => scoreText(value, 2),
    responsive: ['md'],
  },
];

const teacherColumns: TableProps<TeacherRankingItem>['columns'] = [
  { title: '#', width: 64, render: (_, __, index) => rankText(index) },
  {
    title: '老师',
    dataIndex: 'name',
    render: (name, teacher) => <Link to={`/teacher/${teacher.id}`}>{name || '未命名教师'}</Link>,
  },
  { title: '学院', dataIndex: 'dept', responsive: ['md'] },
  { title: '课程数', dataIndex: 'course_count', render: countText },
  { title: '点评数', dataIndex: 'review_count', render: countText },
  { title: '归一化平均分', dataIndex: 'normalized_rate', render: (value) => scoreText(value, 2) },
];

const reviewColumns: TableProps<ReviewRankingItem>['columns'] = [
  { title: '#', width: 64, render: (_, __, index) => rankText(index) },
  {
    title: '课程',
    dataIndex: 'course_name',
    render: (name, review) => (
      <Link to={`/course/${review.course_id}#review-${review.review_id}`}>{name}</Link>
    ),
  },
  {
    title: '作者',
    dataIndex: 'author_name',
    render: (name, review) =>
      review.author ? <Link to={`/user/${review.author.id}`}>{name}</Link> : <span>{name}</span>,
    responsive: ['md'],
  },
  { title: '点赞', dataIndex: 'upvote_count', render: countText },
  {
    title: '长度',
    dataIndex: 'content_length',
    render: (value) => (value ? <span className="mono-text">{value}</span> : '-'),
    responsive: ['lg'],
  },
];

const userColumns: TableProps<UserRankingItem>['columns'] = [
  { title: '#', width: 64, render: (_, __, index) => rankText(index) },
  {
    title: '用户',
    dataIndex: 'user',
    render: (user) => (
      <Link to={`/user/${user.id}`} className="ranking-user-link">
        <UserAvatar size={28} src={user.avatar} name={user.username} />
        <span>{user.username}</span>
      </Link>
    ),
  },
  { title: '点评', dataIndex: 'reviews_count', render: countText },
  { title: '获赞', dataIndex: 'review_upvotes_count', render: countText },
  {
    title: '总长度',
    dataIndex: 'review_length',
    render: (value) => <span className="mono-text">{value || 0}</span>,
    responsive: ['md'],
  },
  { title: '贡献', dataIndex: 'score', render: (value) => scoreText(value, 2) },
];

export function RankingsPage() {
  const rankingsQuery = useRankings(30);
  const rankings = rankingsQuery.data;

  return (
    <div>
      <Seo title="排行榜" description="南方科技大学课程、教师、点评与用户贡献排行榜。" />
      <PageTitle
        title="评课社区排行榜"
        subtitle={
          rankings
            ? `归一化平均分参考全站平均 ${rankings.stats.avg_rate.toFixed(1)} 分、平均 ${rankings.stats.avg_rate_count.toFixed(1)} 个点评。`
            : '按旧 app 口径展示课程、老师、点评和用户贡献榜。'
        }
      />
      <Space orientation="vertical" size={16} className="full-width">
        <Card className="ranking-card" title="最受欢迎的老师">
          <Typography.Paragraph type="secondary">
            至少有 3 门课程评分大于 9 分，且没有课程评分小于 8 分，然后按归一化平均分排序。
          </Typography.Paragraph>
          <Table
            rowKey="id"
            loading={rankingsQuery.isLoading}
            columns={teacherColumns}
            dataSource={rankings?.top_teachers || []}
            pagination={false}
            size="medium"
            scroll={{ x: 'max-content' }}
          />
        </Card>

        <Card className="ranking-card" title="最受欢迎的课程">
          <Typography.Paragraph type="secondary">
            至少 10 个点评，按归一化平均分从高到低排序。
          </Typography.Paragraph>
          <Table
            rowKey="id"
            loading={rankingsQuery.isLoading}
            columns={courseColumns}
            dataSource={rankings?.top_rated_courses || []}
            pagination={false}
            size="medium"
            scroll={{ x: 'max-content' }}
          />
        </Card>

        <Card className="ranking-card" title="点评最多的课程">
          <Table
            rowKey="id"
            loading={rankingsQuery.isLoading}
            columns={courseColumns}
            dataSource={rankings?.popular_courses || []}
            pagination={false}
            size="medium"
            scroll={{ x: 'max-content' }}
          />
        </Card>

        <Card className="ranking-card" title="点赞最多的点评">
          <Typography.Paragraph type="secondary">
            排名要求点评长度大于 500 字节，隐藏、屏蔽、仅学生可见点评不会进入榜单。
          </Typography.Paragraph>
          <Table
            rowKey="review_id"
            loading={rankingsQuery.isLoading}
            columns={reviewColumns}
            dataSource={rankings?.top_reviews || []}
            pagination={false}
            size="medium"
            scroll={{ x: 'max-content' }}
          />
        </Card>

        <Card className="ranking-card" title="最长的点评">
          <Table
            rowKey="review_id"
            loading={rankingsQuery.isLoading}
            columns={reviewColumns}
            dataSource={rankings?.long_reviews || []}
            pagination={false}
            size="medium"
            scroll={{ x: 'max-content' }}
          />
        </Card>

        <Card className="ranking-card" title="贡献最多的用户">
          <Typography.Paragraph type="secondary">
            综合贡献按点评数量、获得点赞和点评总长度加权计算。
          </Typography.Paragraph>
          <Table
            rowKey={(item) => item.user.id}
            loading={rankingsQuery.isLoading}
            columns={userColumns}
            dataSource={rankings?.top_users || []}
            pagination={false}
            size="medium"
            scroll={{ x: 'max-content' }}
          />
        </Card>
      </Space>
    </div>
  );
}
