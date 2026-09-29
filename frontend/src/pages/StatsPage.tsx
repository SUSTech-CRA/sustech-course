import { Card, Col, Row, Statistic, Typography } from 'antd';
import ReactECharts from 'echarts-for-react';

import { PageTitle } from '../components/common/PageTitle';
import { Seo } from '../components/common/Seo';
import { useSiteStats } from '../hooks/useStats';
import type { DistributionPoint, SeriesPoint } from '../types';

const chartTextColor = '#666666';

function barOption(points: DistributionPoint[], name: string, yName: string) {
  return {
    tooltip: { trigger: 'axis' },
    grid: { left: 52, right: 18, top: 28, bottom: 44 },
    xAxis: {
      type: 'category',
      data: points.map((point) => point.label),
      axisLabel: { color: chartTextColor },
    },
    yAxis: { type: 'value', name: yName, axisLabel: { color: chartTextColor } },
    series: [
      {
        name,
        type: 'bar',
        data: points.map((point) => point.value),
        itemStyle: { color: '#337ab7' },
      },
    ],
  };
}

function cumulativeOption(points: SeriesPoint[], barName: string, lineName: string, yName: string) {
  return {
    tooltip: { trigger: 'axis' },
    legend: { top: 0, textStyle: { color: chartTextColor } },
    grid: { left: 52, right: 18, top: 42, bottom: 44 },
    xAxis: {
      type: 'category',
      data: points.map((point) => point.label),
      axisLabel: { color: chartTextColor },
    },
    yAxis: { type: 'value', name: yName, axisLabel: { color: chartTextColor } },
    series: [
      {
        name: barName,
        type: 'bar',
        data: points.map((point) => point.value),
        itemStyle: { color: '#337ab7' },
      },
      {
        name: lineName,
        type: 'line',
        smooth: true,
        data: points.map((point) => point.cumulative || 0),
        itemStyle: { color: '#f0ad4e' },
      },
    ],
  };
}

export function StatsPage() {
  const statsQuery = useSiteStats();
  const stats = statsQuery.data;

  const formatNumber = (value?: number | null, precision = 0) =>
    typeof value === 'number' ? value.toFixed(precision) : '-';

  return (
    <div>
      <Seo title="站点统计" description="NCES 评课社区的课程、教师、用户与点评数据统计。" />
      <PageTitle title="站点统计" subtitle="课程、教师、用户与点评的当前规模和分布。" />
      <Row gutter={[16, 16]}>
        <Col xs={12} md={6}>
          <Card className="section-card">
            <Statistic title="运行天数" value={stats?.running_days || 0} loading={statsQuery.isLoading} />
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card className="section-card">
            <Statistic title="用户" value={stats?.user_count || 0} loading={statsQuery.isLoading} />
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card className="section-card">
            <Statistic title="课程" value={stats?.course_count || 0} loading={statsQuery.isLoading} />
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card className="section-card">
            <Statistic title="点评" value={stats?.review_count || 0} loading={statsQuery.isLoading} />
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card className="section-card">
            <Statistic title="教师" value={stats?.teacher_count || 0} loading={statsQuery.isLoading} />
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card className="section-card">
            <Statistic
              title="注册教师"
              value={stats?.registered_teacher_count || 0}
              loading={statsQuery.isLoading}
            />
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card className="section-card">
            <Statistic
              title="平均评分"
              value={formatNumber(stats?.course_avg_rate, 2)}
              suffix="/ 10"
              loading={statsQuery.isLoading}
            />
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card className="section-card">
            <Statistic
              title="平均每门课点评数"
              value={formatNumber(stats?.course_avg_rate_count, 2)}
              loading={statsQuery.isLoading}
            />
          </Card>
        </Col>
      </Row>
      <Row gutter={[16, 16]}>
        <Col xs={24} lg={12}>
          <Card className="section-card" title="点评评分分布">
            <ReactECharts
              option={barOption(stats?.review_rate_distribution || [], '评分', '点评数量')}
              style={{ height: 320 }}
              showLoading={statsQuery.isLoading}
            />
          </Card>
        </Col>
        <Col xs={24} lg={12}>
          <Card className="section-card" title="课程评分分布">
            <ReactECharts
              option={barOption(stats?.course_rate_distribution || [], '课程平均评分', '课程数')}
              style={{ height: 320 }}
              showLoading={statsQuery.isLoading}
            />
          </Card>
        </Col>
      </Row>
      <Card className="section-card" title="课程点评数量分布">
        <ReactECharts
          option={cumulativeOption(
            stats?.course_review_count_distribution || [],
            '恰好有 N 个点评的课程',
            '至少有 N 个点评的课程',
            '课程数',
          )}
          style={{ height: 360 }}
          showLoading={statsQuery.isLoading}
        />
      </Card>
      <Card className="section-card" title="用户写点评数量分布">
        <ReactECharts
          option={cumulativeOption(
            stats?.user_review_count_distribution || [],
            '恰好写了 N 个点评的用户',
            '至少写了 N 个点评的用户',
            '用户数',
          )}
          style={{ height: 360 }}
          showLoading={statsQuery.isLoading}
        />
      </Card>
      <Row gutter={[16, 16]}>
        <Col xs={24} lg={12}>
          <Card className="section-card" title="每月新增点评数">
            <ReactECharts
              option={cumulativeOption(
                stats?.review_monthly_distribution || [],
                '每月新增点评',
                '总点评数',
                '点评数',
              )}
              style={{ height: 320 }}
              showLoading={statsQuery.isLoading}
            />
          </Card>
        </Col>
        <Col xs={24} lg={12}>
          <Card className="section-card" title="每月新增用户数">
            <ReactECharts
              option={cumulativeOption(
                stats?.user_monthly_distribution || [],
                '每月新增用户',
                '总用户数',
                '用户数',
              )}
              style={{ height: 320 }}
              showLoading={statsQuery.isLoading}
            />
          </Card>
        </Col>
      </Row>
      <Typography.Paragraph type="secondary">
        公开统计只计算当前可见的点评；被隐藏或屏蔽的内容不会进入公开分布。
      </Typography.Paragraph>
    </div>
  );
}
