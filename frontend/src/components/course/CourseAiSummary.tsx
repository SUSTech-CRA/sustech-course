import { DownOutlined, RobotOutlined, UpOutlined } from '@ant-design/icons';
import { Button, Card, Tag, Typography } from 'antd';
import { useId, useState } from 'react';

import type { CourseReviewSummary } from '../../types';
import { formatDateTime } from '../../utils/format';

interface CourseAiSummaryProps {
  summary: CourseReviewSummary;
}

const sections = [
  ['优点', 'strengths'],
  ['槽点与注意事项', 'caveats'],
  ['给分与考核', 'assessment'],
] as const;

export function CourseAiSummary({ summary }: CourseAiSummaryProps) {
  const [expanded, setExpanded] = useState(false);
  const contentId = useId();

  return (
    <Card
      className={`section-card ai-summary-card ${expanded ? 'is-expanded' : 'is-collapsed'}`}
      size="small"
      title={
        <span className="ai-summary-title">
          <RobotOutlined aria-hidden />
          AI 总结
        </span>
      }
      extra={<Tag color="blue">via deepseek-v4-pro</Tag>}
    >
      <div id={contentId} className="ai-summary-content">
        <Typography.Paragraph className="ai-summary-overview">
          {summary.overview}
        </Typography.Paragraph>
        <div className="ai-summary-sections">
          {sections.map(([label, key]) =>
            summary[key].length > 0 ? (
              <section key={key} className="ai-summary-section">
                <Typography.Text strong>{label}</Typography.Text>
                <ul>
                  {summary[key].map((item, index) => (
                    <li key={`${key}-${index}`}>{item}</li>
                  ))}
                </ul>
              </section>
            ) : null,
          )}
        </div>
        <Typography.Text type="secondary" className="ai-summary-meta">
          基于 <span className="mono-text">{summary.source_review_count}</span> 条公开点评 · 生成于{' '}
          {formatDateTime(summary.generated_at)} · AI 生成，仅供参考
        </Typography.Text>
      </div>
      <div className="ai-summary-expand-control">
        <Button
          type="link"
          icon={expanded ? <UpOutlined /> : <DownOutlined />}
          aria-expanded={expanded}
          aria-controls={contentId}
          onClick={() => setExpanded((value) => !value)}
        >
          {expanded ? '收起 AI 总结' : '展开完整总结'}
        </Button>
      </div>
    </Card>
  );
}
