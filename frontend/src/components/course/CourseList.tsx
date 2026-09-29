import { Skeleton } from 'antd';

import type { CourseBrief } from '../../types';
import { EmptyState } from '../common/EmptyState';
import { ItemList } from '../common/ItemList';
import { CourseCard } from './CourseCard';

interface CourseListProps {
  courses?: CourseBrief[];
  loading?: boolean;
}

export function CourseList({ courses = [], loading }: CourseListProps) {
  if (loading) {
    return (
      <div className="stack">
        {Array.from({ length: 4 }).map((_, index) => (
          <Skeleton key={index} active paragraph={{ rows: 2 }} />
        ))}
      </div>
    );
  }

  if (!courses.length) {
    return <EmptyState description="没有找到课程" />;
  }

  return (
    <ItemList
      dataSource={courses}
      rowKey={(course) => course.id}
      renderItem={(course) => <CourseCard course={course} />}
    />
  );
}

