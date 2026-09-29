import { SearchOutlined } from '@ant-design/icons';
import { Card, Input, Pagination, Tabs, Typography } from 'antd';
import { useEffect, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';

import { CourseList } from '../components/course/CourseList';
import { PageTitle } from '../components/common/PageTitle';
import { EmptyState } from '../components/common/EmptyState';
import { Seo } from '../components/common/Seo';
import { ReviewList } from '../components/review/ReviewList';
import { useSearch } from '../hooks/useSearch';
import type { SearchType } from '../types';

const tabItems = [
  { key: 'all', label: '全部' },
  { key: 'course', label: '课程' },
  { key: 'review', label: '点评' },
  { key: 'teacher', label: '教师' },
];

export function SearchPage() {
  const [params, setParams] = useSearchParams();
  const q = params.get('q') || '';
  const type = (params.get('type') || 'all') as SearchType;
  const page = Number(params.get('page') || 1);
  const [input, setInput] = useState(q);
  const resultsRef = useRef<HTMLDivElement>(null);
  const didMountRef = useRef(false);
  const searchQuery = useSearch({ q, type, page, per_page: 10 }, Boolean(q));

  useEffect(() => setInput(q), [q]);

  useEffect(() => {
    if (!didMountRef.current) {
      didMountRef.current = true;
      return;
    }
    resultsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, [q, type, page]);

  const commitSearch = (keyword: string, nextType = type, nextPage = 1) => {
    const value = keyword.trim();
    if (!value) return;
    setParams({ q: value, type: nextType, page: String(nextPage) });
  };

  const renderTeachers = () => {
    const teachers = searchQuery.data?.teachers;
    if (!teachers?.items.length) return <EmptyState description="没有找到教师" />;
    return (
      <div className="result-list">
        {teachers.items.map((teacher) => (
          <Card key={teacher.id} size="small" className="section-card">
            <Typography.Link href={`/teacher/${teacher.id}`}>{teacher.name || '未命名教师'}</Typography.Link>
            <div className="muted-line">{teacher.email || teacher.title || '暂无更多信息'}</div>
          </Card>
        ))}
      </div>
    );
  };

  const activeTotal =
    type === 'course'
      ? searchQuery.data?.courses?.total
      : type === 'review'
        ? searchQuery.data?.reviews?.total
        : type === 'teacher'
          ? searchQuery.data?.teachers?.total
          : 0;

  return (
    <div>
      <Seo title={q ? `搜索：${q}` : '搜索'} description="搜索南方科技大学的课程、教师和点评内容。" noindex />
      <PageTitle title="搜索" subtitle="同时检索课程、老师和点评内容。" />
      <Card className="section-card">
        <Input.Search
          size="large"
          allowClear
          enterButton={<SearchOutlined />}
          placeholder="输入课程名、教师名或点评关键词"
          value={input}
          onChange={(event) => setInput(event.target.value)}
          onSearch={(value) => commitSearch(value)}
        />
      </Card>

      <div ref={resultsRef}>
        <Card className="section-card">
          <Tabs
            activeKey={type}
            items={tabItems}
            onChange={(key) => commitSearch(q || input, key as SearchType)}
          />
          {!q ? (
            <EmptyState description="输入关键词开始搜索" />
          ) : type === 'all' ? (
            <div className="stack">
              <Typography.Title level={4}>课程</Typography.Title>
              <CourseList courses={searchQuery.data?.courses?.items} loading={searchQuery.isLoading} />
              <Typography.Title level={4}>点评</Typography.Title>
              <ReviewList reviews={searchQuery.data?.reviews?.items} loading={searchQuery.isLoading} compact />
              <Typography.Title level={4}>教师</Typography.Title>
              {searchQuery.isLoading ? <EmptyState description="正在搜索教师" /> : renderTeachers()}
            </div>
          ) : type === 'course' ? (
            <CourseList courses={searchQuery.data?.courses?.items} loading={searchQuery.isLoading} />
          ) : type === 'review' ? (
            <ReviewList reviews={searchQuery.data?.reviews?.items} loading={searchQuery.isLoading} compact />
          ) : (
            renderTeachers()
          )}
          {type !== 'all' && (
            <Pagination
              className="pager"
              current={page}
              pageSize={10}
              total={activeTotal || 0}
              showSizeChanger={false}
              onChange={(nextPage) => commitSearch(q, type, nextPage)}
            />
          )}
        </Card>
      </div>
    </div>
  );
}
