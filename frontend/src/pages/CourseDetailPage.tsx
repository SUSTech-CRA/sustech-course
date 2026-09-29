import {
  CheckCircleOutlined,
  DislikeOutlined,
  FilePdfOutlined,
  FolderOpenOutlined,
  HeartFilled,
  HeartOutlined,
  LikeOutlined,
  PlusOutlined,
} from '@ant-design/icons';
import {
  Alert,
  App as AntApp,
  Avatar,
  Button,
  Card,
  Col,
  Pagination,
  Result,
  Row,
  Space,
  Spin,
  Table,
  Tabs,
  Tag,
  Typography,
} from 'antd';
import type { TableProps } from 'antd';
import { Link, useLocation, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { lazy, Suspense, useEffect, useMemo, useRef, useState } from 'react';

import { getApiErrorMessage } from '../api/client';
import { CourseRatingSummary } from '../components/course/CourseRatingSummary';
import { CourseAiSummary } from '../components/course/CourseAiSummary';
import { HTMLContent } from '../components/common/HTMLContent';
import { PageTitle } from '../components/common/PageTitle';
import { Seo } from '../components/common/Seo';
import { ReviewFilter } from '../components/review/ReviewFilter';
import { ReviewList } from '../components/review/ReviewList';
import {
  useCourse,
  useCourseMutations,
  useCourseReviews,
} from '../hooks/useCourse';
import { useReview } from '../hooks/useReview';
import { useAuthStore } from '../stores/authStore';
import type { CourseBrief, CourseTermResponse, ReviewSortBy } from '../types';
import {
  compactTeacherNames,
  stripHtmlForSummary,
  termDisplay,
  termListDisplay,
} from '../utils/format';
import { FALLBACK_TEACHER_IMAGE } from '../utils/constants';
import { buildSignInPath, getRedirectFromLocation } from '../utils/authRedirect';

// 图表组件单独懒加载，echarts vendor chunk 只在用户点开"点评统计" tab 时才下载
const CourseStatsCharts = lazy(async () => ({
  default: (await import('../components/course/CourseStatsCharts')).CourseStatsCharts,
}));

export function CourseDetailPage() {
  const { id } = useParams();
  const location = useLocation();
  const navigate = useNavigate();
  const [reviewParams, setReviewParams] = useSearchParams();
  const { message } = AntApp.useApp();
  const user = useAuthStore((state) => state.user);
  const [syllabusState, setSyllabusState] = useState<'checking' | 'available' | 'missing'>('checking');
  const reviewsRef = useRef<HTMLDivElement>(null);
  const didReviewScrollRef = useRef(false);
  const page = Math.max(Number(reviewParams.get('page') || 1), 1);
  const sortBy = (reviewParams.get('sort_by') || 'upvote') as ReviewSortBy;
  const term = reviewParams.get('term') || undefined;
  const ratingValue = Number(reviewParams.get('rating'));
  const rating = Number.isFinite(ratingValue) && ratingValue > 0 ? ratingValue : undefined;
  const courseQuery = useCourse(id);
  const reviewsQuery = useCourseReviews(id, {
    page,
    per_page: 20,
    sort_by: sortBy,
    term,
    rating,
  });
  const courseMutations = useCourseMutations(id);
  const targetReviewId = useMemo(() => {
    const match = location.hash.match(/^#review-(\d+)$/);
    return match?.[1];
  }, [location.hash]);
  const targetReviewQuery = useReview(targetReviewId);
  const course = courseQuery.data;
  const syllabusCode = course?.courseries || course?.course_code;
  const syllabusUrl = syllabusCode
    ? `https://mirrors.sustech.edu.cn/courses/syllabus/${encodeURIComponent(syllabusCode)}.pdf`
    : undefined;
  const signInPath = buildSignInPath(getRedirectFromLocation(location));

  const updateReviewParams = (updates: Record<string, string | number | undefined>) => {
    const next = new URLSearchParams(reviewParams);
    Object.entries(updates).forEach(([key, value]) => {
      if (value === undefined || value === '' || (key === 'page' && Number(value) <= 1)) {
        next.delete(key);
      } else if (key === 'sort_by' && value === 'upvote') {
        next.delete(key);
      } else {
        next.set(key, String(value));
      }
    });
    setReviewParams(next);
  };

  useEffect(() => {
    if (!location.hash) return;
    const timer = window.setTimeout(() => {
      const target = document.getElementById(location.hash.slice(1));
      target?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 120);
    return () => window.clearTimeout(timer);
  }, [location.hash, reviewsQuery.data, targetReviewQuery.data]);

  useEffect(() => {
    if (!didReviewScrollRef.current) {
      didReviewScrollRef.current = true;
      return;
    }
    if (location.hash) return;
    reviewsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, [page, sortBy, term, rating, location.hash]);

  useEffect(() => {
    if (!syllabusUrl) {
      setSyllabusState('missing');
      return;
    }
    let cancelled = false;
    setSyllabusState('checking');
    fetch(syllabusUrl, { method: 'HEAD' })
      .then((response) => {
        if (!cancelled) setSyllabusState(response.ok ? 'available' : 'missing');
      })
      .catch(() => {
        if (!cancelled) setSyllabusState('missing');
      });
    return () => {
      cancelled = true;
    };
  }, [syllabusUrl]);

  if (courseQuery.isLoading) {
    return <Spin fullscreen description="加载课程详情" />;
  }

  if (courseQuery.isError || !course) {
    return <Result status="404" title="课程不存在或暂时无法访问" />;
  }

  const rate = course.rate;
  const reviewPath = `/course/${course.id}/review`;
  const materialPath = `/course/${course.id}/material`;
  const syllabusButtonText =
    syllabusState === 'available'
      ? '课程大纲 PDF'
      : syllabusState === 'checking'
        ? '检查课程大纲'
        : '暂未收录课程大纲';
  const seoDescription =
    stripHtmlForSummary(course.description, 140) ||
    stripHtmlForSummary(course.introduction, 140) ||
    `${course.name}课程点评与评分${course.teachers.length ? ' - 任课教师：' + compactTeacherNames(course.teachers.map((t) => t.name).filter(Boolean).join('、')) : ''}`;
  const courseJsonLd = {
    '@context': 'https://schema.org',
    '@type': 'Course',
    name: course.name,
    description: seoDescription,
    provider: {
      '@type': 'CollegeOrUniversity',
      name: 'Niuwa Curriculum Evaluation System',
      sameAs: 'https://ncesnext.com/',
    },
    ...(rate && rate.review_count > 0 && rate.rate_average
      ? {
          aggregateRating: {
            '@type': 'AggregateRating',
            ratingValue: rate.rate_average,
            bestRating: 10,
            worstRating: 1,
            ratingCount: rate.review_count,
          },
        }
      : {}),
  };
  const courseTerms = course.terms.map((item) => item.term).filter(Boolean) as string[];
  const latestCourseTerm = course.terms[0];
  const infoItems = [
    { key: 'join_type', label: '选课类别', value: latestCourseTerm?.join_type },
    { key: 'course_type', label: '课程类别', value: course.course_type || latestCourseTerm?.course_type },
    { key: 'teaching_type', label: '教学语言', value: latestCourseTerm?.teaching_type },
    {
      key: 'dept',
      label: '开课单位',
      value: course.dept || course.course_major || latestCourseTerm?.course_major,
    },
    { key: 'course_level', label: '课程层次', value: latestCourseTerm?.course_level },
    { key: 'credit', label: '学分', value: course.credit ?? latestCourseTerm?.credit },
    {
      key: 'grading_type',
      label: '考核方式',
      value: course.grading_type || latestCourseTerm?.grading_type,
    },
    { key: 'hours_per_week', label: '周学时', value: course.hours_per_week ?? latestCourseTerm?.hours_per_week },
    { key: 'hours', label: '总学时', value: course.hours ?? latestCourseTerm?.hours },
    { key: 'campus', label: '校区', value: course.campus || latestCourseTerm?.campus },
  ].filter((item) => item.value !== null && item.value !== undefined && item.value !== '');

  const termColumns: TableProps<CourseTermResponse>['columns'] = [
    { title: '学期', dataIndex: 'term', render: (value) => <span className="mono-text">{termDisplay(value)}</span> },
    { title: '课程号', dataIndex: 'courseries', render: (value) => <span className="mono-text">{value || '-'}</span> },
    { title: '课程类别', dataIndex: 'course_type' },
    { title: '教学类型', dataIndex: 'teaching_type' },
    { title: '考核方式', dataIndex: 'grading_type' },
    { title: '学分', dataIndex: 'credit' },
    { title: '周学时', dataIndex: 'hours_per_week' },
  ];

  const requireLogin = () => {
    if (!user) {
      message.info('请先登录');
      navigate(signInPath);
      return false;
    }
    return true;
  };

  const runAction = async (action: 'upvote' | 'downvote' | 'follow' | 'join', enabled: boolean) => {
    if (!requireLogin()) return;
    try {
      await courseMutations[action].mutateAsync(enabled);
      message.success('操作已更新');
    } catch (error) {
      message.error(getApiErrorMessage(error));
    }
  };

  const renderCourseActionButtons = () => [
    <Button
      key="follow"
      icon={course.is_following ? <HeartFilled /> : <HeartOutlined />}
      onClick={() => runAction('follow', !course.is_following)}
    >
      {course.is_following ? '已关注' : '关注'} · {rate?.follow_count || 0}
    </Button>,
    <Button
      key="upvote"
      icon={<LikeOutlined />}
      type={course.is_upvoted ? 'primary' : 'default'}
      onClick={() => runAction('upvote', !course.is_upvoted)}
    >
      {course.is_upvoted ? '已推荐' : '推荐'} · {rate?.upvote_count || 0}
    </Button>,
    <Button
      key="downvote"
      danger={course.is_downvoted}
      icon={<DislikeOutlined />}
      onClick={() => runAction('downvote', !course.is_downvoted)}
    >
      {course.is_downvoted ? '已不推荐' : '不推荐'} · {rate?.downvote_count || 0}
    </Button>,
  ];

  const renderCourseSummary = (courseItem: CourseBrief, mode: 'related' | 'same_teacher') => (
    <Link key={courseItem.id} to={`/course/${courseItem.id}`} className="related-course-row">
      <span className="related-course-main">
        <Typography.Text strong className="related-course-title">
          {mode === 'related' ? compactTeacherNames(courseItem.teacher_names) : courseItem.name}
        </Typography.Text>
        <span className="related-course-meta">
          {courseItem.course_code && <Tag className="mono-text">{courseItem.course_code}</Tag>}
          <Typography.Text type="secondary" className="mono-text">
            {termListDisplay(courseItem.term_ids, 2)}
          </Typography.Text>
        </span>
      </span>
      <span className="related-course-score">
        <Typography.Text strong className="mono-text related-course-score-value">
          {courseItem.rate_average ? Number(courseItem.rate_average).toFixed(1) : '暂无'}
        </Typography.Text>
        {courseItem.review_count > 0 && (
          <Typography.Text type="secondary" className="mono-text">
            ({courseItem.review_count})
          </Typography.Text>
        )}
      </span>
    </Link>
  );

  const tabs = [
    {
      key: 'reviews',
      label: `点评 ${reviewsQuery.data?.total ?? rate?.review_count ?? 0}`,
      children: (
        <div>
          {course.num_blocked_reviews > 0 && (
            <Alert
              type="warning"
              className="review-notice"
              title={
                <Typography.Text strong>
                  本页面有 {course.num_blocked_reviews} 条评论因违反
                  <Link to="/community-rules">社区规范</Link>
                  被隐藏，请同学们文明点评，遵守社区规范。
                </Typography.Text>
              }
            />
          )}
          {course.num_deleted_reviews > 0 && (
            <Alert
              type="warning"
              className="review-notice"
              title={
                <Typography.Text strong>
                  本课程有 {course.num_deleted_reviews} 位用户曾删除过点评。
                </Typography.Text>
              }
            />
          )}
          <ReviewFilter
            sortBy={sortBy}
            term={term}
            rating={rating}
            termOptions={course.review_term_list}
            onSortChange={(value) => {
              updateReviewParams({ sort_by: value, page: 1 });
            }}
            onTermChange={(value) => {
              updateReviewParams({ term: value, page: 1 });
            }}
            onRatingChange={(value) => {
              updateReviewParams({ rating: value, page: 1 });
            }}
          />
          {targetReviewQuery.data &&
            !reviewsQuery.data?.items.some((review) => review.id === targetReviewQuery.data?.id) && (
              <Card size="small" className="target-review-card" title="定位到的点评">
                <ReviewList reviews={[targetReviewQuery.data]} />
              </Card>
            )}
          <ReviewList reviews={reviewsQuery.data?.items} loading={reviewsQuery.isLoading} />
          <Pagination
            className="pager"
            current={reviewsQuery.data?.page || page}
            pageSize={reviewsQuery.data?.per_page || 20}
            total={reviewsQuery.data?.total || 0}
            showSizeChanger={false}
            onChange={(nextPage) => updateReviewParams({ page: nextPage })}
          />
        </div>
      ),
    },
    {
      key: 'stats',
      label: '点评统计',
      children: (
        <Suspense fallback={<Card size="small" loading />}>
          <CourseStatsCharts courseId={course.id} />
        </Suspense>
      ),
    },
    {
      key: 'terms',
      label: '开课记录',
      children: (
        <Table
          size="small"
          rowKey="id"
          columns={termColumns}
          dataSource={course.terms}
          pagination={false}
          scroll={{ x: 720 }}
        />
      ),
    },
  ];

  return (
    <>
      <Seo
        title={course.course_code ? `${course.name}（${course.course_code}）` : course.name}
        description={seoDescription}
        jsonLd={courseJsonLd}
      />
      <Row gutter={[20, 20]}>
      <Col xs={24} lg={17}>
        <PageTitle
          title={course.name}
          subtitle={
            <Space wrap>
              {course.course_code && <Tag className="mono-text">{course.course_code}</Tag>}
              <span className="mono-text">{termListDisplay(courseTerms, courseTerms.length)}</span>
              <span>{course.teachers.map((teacher) => teacher.name).filter(Boolean).join('、') || '教师未知'}</span>
              <span>{course.access_count || 0} 次浏览</span>
            </Space>
          }
          extra={
            <Space>
              {user && (
                <Button onClick={() => navigate(`/course/${course.id}/edit`)}>编辑课程介绍</Button>
              )}
              <Button
                type="primary"
                icon={course.has_reviewed ? <CheckCircleOutlined /> : <PlusOutlined />}
                onClick={() => navigate(user ? reviewPath : buildSignInPath(reviewPath))}
              >
                {course.has_reviewed ? '编辑/查看我的点评' : '写点评'}
              </Button>
            </Space>
          }
        />
        <CourseRatingSummary course={course} />
        <Card className="section-card course-info-card" size="small" title="课程信息">
          <div className="stack">
            {infoItems.length > 0 && (
              <div className="course-info-grid">
                {infoItems.map((item) => (
                  <div key={item.key} className="course-info-item">
                    <Typography.Text type="secondary" className="course-info-label">
                      {item.label}
                    </Typography.Text>
                    <Typography.Text className="course-info-value">{item.value}</Typography.Text>
                  </div>
                ))}
              </div>
            )}
            {course.homepage && (
              <Alert
                type="info"
                showIcon
                title="课程主页"
                description={
                  <Typography.Link href={course.homepage} target="_blank">
                    {course.homepage}
                  </Typography.Link>
                }
              />
            )}
            {course.admin_announcement && (
              <Alert
                type="warning"
                showIcon
                title="管理员公告"
                description={<HTMLContent html={course.admin_announcement} />}
              />
            )}
            <div className="course-actions-inline">
              {renderCourseActionButtons()}
            </div>
            <div className="course-resource-panel">
              {syllabusState === 'available' && syllabusUrl ? (
                <Button icon={<FilePdfOutlined />} href={syllabusUrl} target="_blank" rel="noreferrer">
                  {syllabusButtonText}
                </Button>
              ) : (
                <Button icon={<FilePdfOutlined />} disabled loading={syllabusState === 'checking'}>
                  {syllabusButtonText}
                </Button>
              )}
              {user ? (
                <Link to={materialPath}>
                  <Button icon={<FolderOpenOutlined />}>课程公开课件/试卷</Button>
                </Link>
              ) : (
                <Button icon={<FolderOpenOutlined />} onClick={() => navigate(buildSignInPath(materialPath))}>
                  登录后查看课件/试卷
                </Button>
              )}
            </div>
            <div className="course-info-block">
              <Typography.Title level={3} className="card-section-title">
                课程简介（教工部数据）
              </Typography.Title>
              <Typography.Paragraph>{course.description || '暂无课程简介'}</Typography.Paragraph>
              {course.description_eng && (
                <Typography.Paragraph type="secondary">{course.description_eng}</Typography.Paragraph>
              )}
            </div>
            <div className="course-info-block">
              <Typography.Title level={3} className="card-section-title">
                课程信息（同学贡献）
              </Typography.Title>
              <HTMLContent html={course.introduction} />
            </div>
          </div>
        </Card>
        {course.ai_summary && <CourseAiSummary summary={course.ai_summary} />}
        <div ref={reviewsRef}>
          <Card className="section-card">
            <Tabs items={tabs} />
          </Card>
        </div>
      </Col>

      <Col xs={24} lg={7}>
        <div className="side-stack">
          <Card className="section-card" size="small" title="任课教师">
            <Space orientation="vertical" className="full-width">
              {course.teachers.length ? (
                course.teachers.map((teacher) => (
                  <Link key={teacher.id} to={`/teacher/${teacher.id}`} className="teacher-row">
                    <Avatar size={42} src={teacher.image || FALLBACK_TEACHER_IMAGE} />
                    <span className="teacher-row-main">
                      <Typography.Text strong>{teacher.name || '未命名教师'}</Typography.Text>
                      <Typography.Text type="secondary">{teacher.title || teacher.email || '暂无更多信息'}</Typography.Text>
                    </span>
                  </Link>
                ))
              ) : (
                <Typography.Text type="secondary">暂无教师信息</Typography.Text>
              )}
            </Space>
          </Card>

          {course.related_courses.length > 0 && (
            <Card className="section-card related-course-card" size="small" title={`其他老师的「${course.name}」课`}>
              <div className="related-course-list">
                {course.related_courses.map((item) => renderCourseSummary(item, 'related'))}
              </div>
            </Card>
          )}

          {course.same_teacher_courses.map((group) => (
            <Card
              key={group.teacher.id}
              className="section-card related-course-card"
              size="small"
              title={`${group.teacher.name || '这位老师'}的其他课`}
            >
              <div className="related-course-list">
                {group.courses.map((item) => renderCourseSummary(item, 'same_teacher'))}
              </div>
            </Card>
          ))}
          {/* {course.latest_score && (
            <Card className="section-card" size="small" title="历年成绩">
              <HTMLContent html={course.latest_score} />
            </Card>
          )} */}
        </div>
      </Col>
      </Row>
    </>
  );
}
