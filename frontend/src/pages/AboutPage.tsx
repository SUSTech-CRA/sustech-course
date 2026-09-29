import { Card, Col, Row, Statistic, Tabs } from 'antd';
import DOMPurify from 'dompurify';
import { marked } from 'marked';
import { useEffect, useMemo, useState } from 'react';
import { useLocation } from 'react-router-dom';

import { PageTitle } from '../components/common/PageTitle';
import { Seo } from '../components/common/Seo';
import { aboutSections } from '../content/aboutContent';
import { useSiteStats } from '../hooks/useStats';

const ABOUT_SEO_TITLES: Record<string, string> = {
  about: '关于我们',
  rules: '社区规范',
  report: '投诉点评',
};

function getDefaultKey(pathname: string) {
  if (pathname.includes('community-rules')) return 'rules';
  if (pathname.includes('report-review')) return 'report';
  return 'about';
}

function renderMarkdown(markdown: string) {
  return DOMPurify.sanitize(marked.parse(markdown, { async: false }) as string);
}

export function AboutPage() {
  const location = useLocation();
  const statsQuery = useSiteStats();
  const defaultKey = getDefaultKey(location.pathname);
  const [activeKey, setActiveKey] = useState(defaultKey);
  const tabItems = useMemo(
    () =>
      aboutSections.map((section) => ({
        key: section.key,
        label: section.title,
        children: (
          <div
            className="html-content-body static-doc"
            dangerouslySetInnerHTML={{ __html: renderMarkdown(section.markdown) }}
          />
        ),
      })),
    [],
  );

  useEffect(() => {
    setActiveKey(defaultKey);
  }, [defaultKey]);

  return (
    <div>
      <Seo
        title={ABOUT_SEO_TITLES[activeKey] || '关于我们'}
        description="了解 NCES 评课社区：南科大课程评价社区的介绍、社区规范与点评举报方式。"
      />
      <PageTitle title="关于 NCES" subtitle="Niuwa Curriculum Evaluation System" />
      <Row gutter={[12, 12]}>
        <Col xs={12} md={6}>
          <Card className="section-card">
            <Statistic title="运行天数" value={statsQuery.data?.running_days || 0} loading={statsQuery.isLoading} />
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card className="section-card">
            <Statistic title="用户" value={statsQuery.data?.user_count || 0} loading={statsQuery.isLoading} />
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card className="section-card">
            <Statistic title="课程" value={statsQuery.data?.course_count || 0} loading={statsQuery.isLoading} />
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card className="section-card">
            <Statistic title="点评" value={statsQuery.data?.review_count || 0} loading={statsQuery.isLoading} />
          </Card>
        </Col>
      </Row>
      <Card className="section-card">
        <Tabs activeKey={activeKey} onChange={(key) => setActiveKey(key as typeof activeKey)} items={tabItems} />
      </Card>
    </div>
  );
}
