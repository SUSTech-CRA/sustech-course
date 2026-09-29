import { Card, Empty } from 'antd';
import ReactECharts from 'echarts-for-react';

import { useCourseStats } from '../../hooks/useCourse';
import { termDisplay } from '../../utils/format';

const chartTextColor = '#666666';

// 该组件被 CourseDetailPage 懒加载：echarts vendor chunk 只在用户打开"点评统计" tab 时才下载
export function CourseStatsCharts({ courseId }: { courseId: number }) {
  const statsQuery = useCourseStats(courseId);
  const stats = statsQuery.data;

  const ratingDist = stats?.rating_distribution || {};
  const ratingOption = {
    tooltip: { trigger: 'axis' },
    grid: { left: 40, right: 20, top: 30, bottom: 30 },
    xAxis: {
      type: 'category',
      data: Array.from({ length: 10 }, (_, i) => `${i + 1}分`),
      axisLabel: { color: chartTextColor },
    },
    yAxis: { type: 'value', minInterval: 1, axisLabel: { color: chartTextColor } },
    series: [
      {
        name: '点评数量',
        type: 'bar',
        data: Array.from({ length: 10 }, (_, i) => ratingDist[String(i + 1)] || 0),
        itemStyle: { color: '#337ab7', opacity: 0.55 },
      },
    ],
  };

  const termStats = stats?.term_stats || [];
  const trendOption = {
    tooltip: { trigger: 'axis' },
    legend: { top: 0, textStyle: { color: chartTextColor } },
    grid: { left: 46, right: 46, top: 42, bottom: 56 },
    xAxis: {
      type: 'category',
      data: termStats.map((item) => termDisplay(item.term)),
      axisLabel: { color: chartTextColor, rotate: 45 },
    },
    yAxis: [
      { type: 'value', name: '平均分', min: 0, max: 10, axisLabel: { color: chartTextColor } },
      { type: 'value', name: '点评数量', minInterval: 1, axisLabel: { color: chartTextColor } },
    ],
    series: [
      {
        name: '点评数量',
        type: 'bar',
        yAxisIndex: 1,
        data: termStats.map((item) => item.review_count),
        itemStyle: { color: '#337ab7', opacity: 0.55 },
      },
      {
        name: '平均分',
        type: 'line',
        yAxisIndex: 0,
        smooth: true,
        symbolSize: 8,
        data: termStats.map((item) =>
          item.rate_average == null ? null : Number(item.rate_average.toFixed(1)),
        ),
        itemStyle: { color: '#f0ad4e' },
        lineStyle: { color: '#f0ad4e', width: 3 },
      },
    ],
  };

  if (stats && !termStats.length && !Object.keys(ratingDist).length) {
    return (
      <Card size="small">
        <Empty description="暂无点评数据" />
      </Card>
    );
  }

  return (
    <div className="stack">
      <Card size="small" title="学期评分趋势">
        <ReactECharts option={trendOption} style={{ height: 320 }} showLoading={statsQuery.isLoading} />
      </Card>
      <Card size="small" title="评分分布">
        <ReactECharts option={ratingOption} style={{ height: 280 }} showLoading={statsQuery.isLoading} />
      </Card>
    </div>
  );
}
