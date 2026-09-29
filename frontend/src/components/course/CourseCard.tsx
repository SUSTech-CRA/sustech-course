import { TeamOutlined } from '@ant-design/icons';
import { Progress, Tag, Typography } from 'antd';
import { Link } from 'react-router-dom';

import type { CourseBrief } from '../../types';
import { compactTeacherNames, termListDisplay } from '../../utils/format';
import { SearchHighlight } from '../common/SearchHighlight';
import { StarRating } from '../common/StarRating';

interface CourseCardProps {
  course: CourseBrief;
}

const COURSE_METRIC_LABELS = [
  ['难度', 'difficulty_score'],
  ['作业', 'homework_score'],
  ['给分', 'grading_score'],
  ['收获', 'gain_score'],
] as const;

function parseMetricScore(value?: string | null) {
  const score = Number(value);
  if (!Number.isFinite(score)) return undefined;
  return Math.max(0, Math.min(100, score));
}

function formatMetricScore(score: number) {
  return String(Math.round(score));
}

export function CourseCard({ course }: CourseCardProps) {
  // 没有点评时聚合分是无意义的 0，展示"暂无"而非数字
  const hasReviews = course.review_count > 0;
  const metrics = COURSE_METRIC_LABELS.flatMap(([label, key]) => {
    const score = parseMetricScore(course[key]);
    return score === undefined ? [] : [{ label, score }];
  });

  return (
    <Link to={`/course/${course.id}`} className="course-list-row">
      <div className="course-card-main">
        <div className="course-card-content">
          <div className="course-card-heading">
            <Typography.Title level={2} className="course-card-title">
              {course.name_highlighted ? <SearchHighlight html={course.name_highlighted} /> : course.name}
            </Typography.Title>
            {course.course_code && <Tag className="mono-text">{course.course_code}</Tag>}
            <Typography.Text type="secondary" className="mono-text">
              {termListDisplay(course.term_ids, 2)}
            </Typography.Text>
          </div>
          <div className="muted-line">
            <TeamOutlined /> {compactTeacherNames(course.teacher_names)}
          </div>
        </div>
        <div className="course-card-rating">
          <StarRating value={course.rate_average} count={course.review_count} showText size="small" />
        </div>
        {metrics.length > 0 && (
          <div className="course-card-metrics">
            {metrics.map((metric) => (
              <span key={metric.label} className="course-card-metric">
                <span className="course-card-metric-head">
                  <Typography.Text type="secondary">{metric.label}</Typography.Text>
                  {hasReviews ? (
                    <Typography.Text strong className="mono-text">
                      {formatMetricScore(metric.score)}
                    </Typography.Text>
                  ) : (
                    <Typography.Text type="secondary">暂无</Typography.Text>
                  )}
                </span>
                <Progress
                  percent={hasReviews ? metric.score : 0}
                  showInfo={false}
                  size={{ height: 3 }}
                  strokeColor="var(--color-primary)"
                  railColor="var(--color-border-subtle)"
                  aria-label={`${metric.label} ${hasReviews ? formatMetricScore(metric.score) : '暂无'}`}
                />
              </span>
            ))}
          </div>
        )}
      </div>
    </Link>
  );
}
