import { LinkOutlined, MailOutlined, PhoneOutlined } from '@ant-design/icons';
import { useQuery } from '@tanstack/react-query';
import { Avatar, Button, Card, Result, Space, Spin, Tag, Typography } from 'antd';
import { Link, useParams } from 'react-router-dom';

import { teachersApi } from '../api/teachers';
import { CourseList } from '../components/course/CourseList';
import { HTMLContent } from '../components/common/HTMLContent';
import { Seo } from '../components/common/Seo';
import { FALLBACK_TEACHER_IMAGE } from '../utils/constants';
import { useAuthStore } from '../stores/authStore';
import { stripHtmlForSummary } from '../utils/format';

export function TeacherProfilePage() {
  const { id } = useParams();
  const user = useAuthStore((state) => state.user);
  const teacherQuery = useQuery({
    queryKey: ['teacher', id],
    queryFn: () => teachersApi.detail(id as string),
    enabled: Boolean(id),
  });

  if (teacherQuery.isLoading) return <Spin fullscreen description="加载教师主页" />;
  if (!teacherQuery.data) return <Result status="404" title="教师不存在或无法访问" />;

  const teacher = teacherQuery.data;
  const teacherName = teacher.name || '未命名教师';
  const homepage = teacher.homepage && teacher.homepage !== 'http://' ? teacher.homepage : null;
  const seoDescription =
    stripHtmlForSummary(teacher.research_interest, 140) ||
    stripHtmlForSummary(teacher.description, 140) ||
    `${teacher.name || '教师'}${teacher.title ? `（${teacher.title}）` : ''}的课程点评与评分`;
  const teacherJsonLd = {
    '@context': 'https://schema.org',
    '@type': 'Person',
    name: teacher.name || undefined,
    jobTitle: teacher.title || undefined,
    email: teacher.email || undefined,
    image: teacher.image || undefined,
    worksFor: {
      '@type': 'CollegeOrUniversity',
      name: '南方科技大学',
    },
  };

  const sideColumn = (
    <>
      <Card className="section-card profile-side-card">
        <div className="profile-side-head">
          <Avatar size={96} src={teacher.image || FALLBACK_TEACHER_IMAGE} alt={teacherName} />
          <Typography.Title level={4} className="profile-side-name">
            {teacherName}
          </Typography.Title>
          {teacher.title && (
            <Space size={4} wrap className="profile-side-badges">
              <Tag color="green">{teacher.title}</Tag>
            </Space>
          )}
        </div>
        {teacher.research_interest && (
          <div className="profile-side-description">
            <div className="profile-side-section-label">研究方向</div>
            <HTMLContent html={teacher.research_interest} />
          </div>
        )}
        <ul className="profile-side-meta">
          {teacher.email && (
            <li>
              <MailOutlined /> <a href={`mailto:${teacher.email}`}>{teacher.email}</a>
            </li>
          )}
          {teacher.office_phone && (
            <li>
              <PhoneOutlined /> {teacher.office_phone}
            </li>
          )}
          {homepage && (
            <li>
              教师主页：
              <a href={homepage} target="_blank" rel="noopener noreferrer">
                <LinkOutlined /> 戳这里
              </a>
            </li>
          )}
          <li>
            主页访问 <span className="mono-font">{teacher.access_count || 0}</span> 次
          </li>
        </ul>
        {user && (
          <Link to={`/teacher/${teacher.id}/edit`}>
            <Button block>编辑教师信息</Button>
          </Link>
        )}
      </Card>
      <Card className="section-card profile-side-card">
        <ul className="profile-side-stats">
          <li>
            共 <span className="mono-font">{teacher.courses.length}</span> 门课
          </li>
          <li>
            共 <span className="mono-font">{teacher.review_count}</span> 个点评
          </li>
          <li>
            平均分: <span className="mono-font">{teacher.review_count ? teacher.average_rate.toFixed(2) : '-'}</span>
          </li>
          <li>
            归一化平均分:{' '}
            <span className="mono-font">{teacher.review_count ? teacher.normalized_rate.toFixed(2) : '-'}</span>
          </li>
        </ul>
      </Card>
    </>
  );

  return (
    <div>
      <Seo title={teacherName} description={seoDescription} jsonLd={teacherJsonLd} />
      <div className="profile-layout">
        <div className="profile-layout-side">{sideColumn}</div>
        <div className="profile-layout-main">
          {teacher.description && (
            <Card className="section-card" title="教师介绍">
              <HTMLContent html={teacher.description} />
            </Card>
          )}
          <Card
            className="section-card"
            title={
              <Space size={8} wrap>
                <Typography.Text strong>{teacherName} 老师的课程</Typography.Text>
                <Typography.Text type="secondary" className="profile-course-count">
                  {teacher.courses.length ? `（共 ${teacher.courses.length} 门）` : '还没有课程哦！'}
                </Typography.Text>
              </Space>
            }
          >
            <CourseList courses={teacher.courses} />
          </Card>
        </div>
      </div>
    </div>
  );
}
