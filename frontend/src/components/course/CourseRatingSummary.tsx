import { Card, Col, Progress, Row, Typography } from 'antd';

import type { CourseDetail } from '../../types';
import { percentValue } from '../../utils/format';
import { StarRating } from '../common/StarRating';

interface CourseRatingSummaryProps {
  course: CourseDetail;
}

const metricLabels = [
  ['课程难度', 'difficulty', 'difficulty_score'],
  ['作业多少', 'homework', 'homework_score'],
  ['给分好坏', 'grading', 'grading_score'],
  ['收获大小', 'gain', 'gain_score'],
] as const;

function formatMetricScore(score: number) {
  return String(Math.round(score));
}

export function CourseRatingSummary({ course }: CourseRatingSummaryProps) {
  const rate = course.rate;
  const average = rate?.average_rate ?? rate?.rate_average ?? null;
  const metrics = metricLabels.map(([label, valueKey, scoreKey]) => {
    const rawScore = rate?.[scoreKey];
    return {
      label,
      value: rate?.[valueKey] || '暂无',
      score: rawScore === null || rawScore === undefined || rawScore === '' ? null : percentValue(rawScore),
    };
  });

  return (
    <Card className="section-card rating-summary-card" size="small">
      <Row gutter={[18, 14]} align="middle">
        <Col xs={24} xl={8} className="rating-summary-score">
          <Typography.Text type="secondary" className="rating-summary-label">
            综合评分
          </Typography.Text>
          <StarRating value={average} count={rate?.review_count ?? course.rate?.review_count ?? 0} />
        </Col>
        <Col xs={24} xl={16}>
          <div className="rating-summary-metrics">
            {metrics.map((metric) => (
              <div key={metric.label} className="rating-summary-metric">
                <div className="rating-summary-metric-head">
                  <Typography.Text type="secondary">{metric.label}</Typography.Text>
                  <span className="rating-summary-metric-value">
                    <Typography.Text strong>{metric.value}</Typography.Text>
                    {metric.score !== null && (
                      <Typography.Text type="secondary" className="mono-text">
                        {formatMetricScore(metric.score)}
                      </Typography.Text>
                    )}
                  </span>
                </div>
                <Progress
                  percent={metric.score ?? 0}
                  showInfo={false}
                  size={{ height: 4 }}
                  strokeColor="var(--color-primary)"
                  railColor="var(--color-border-subtle)"
                  aria-label={`${metric.label} ${metric.score === null ? '暂无' : formatMetricScore(metric.score)}`}
                />
              </div>
            ))}
          </div>
        </Col>
      </Row>
    </Card>
  );
}
