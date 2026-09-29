import { Card, Pagination } from 'antd';
import { useEffect, useRef } from 'react';
import { useSearchParams } from 'react-router-dom';

import { CourseFilter } from '../components/course/CourseFilter';
import { CourseList } from '../components/course/CourseList';
import { PageTitle } from '../components/common/PageTitle';
import { Seo } from '../components/common/Seo';
import { useCourseFilterOptions, useCourses } from '../hooks/useCourse';
import type { CourseSortBy } from '../types';

export function CourseListPage() {
  const [params, setParams] = useSearchParams();
  const page = Number(params.get('page') || 1);
  const sortBy = (params.get('sort_by') || 'rate') as CourseSortBy;
  const courseType = params.get('course_type') || undefined;
  const offeringUnit = params.get('offering_unit') || undefined;
  const listRef = useRef<HTMLDivElement>(null);
  const didMountRef = useRef(false);
  const coursesQuery = useCourses({
    page,
    per_page: 20,
    sort_by: sortBy,
    course_type: courseType,
    offering_unit: offeringUnit,
  });
  const filterOptionsQuery = useCourseFilterOptions();

  const updateParams = (next: Record<string, string | undefined>) => {
    const merged = new URLSearchParams(params);
    Object.entries(next).forEach(([key, value]) => {
      if (value) merged.set(key, value);
      else merged.delete(key);
    });
    if (!next.page) merged.set('page', '1');
    setParams(merged);
  };

  useEffect(() => {
    if (!didMountRef.current) {
      didMountRef.current = true;
      return;
    }
    listRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, [page, sortBy, courseType, offeringUnit]);

  return (
    <div>
      <Seo title="课程列表" description="浏览南方科技大学全部课程，按课程类别、开课单位和评分筛选课程。" />
      <PageTitle
        title="课程列表"
        subtitle={`共 ${coursesQuery.data?.total || 0} 门课程`}
      />
      <div ref={listRef}>
        <Card className="section-card course-list-panel">
          <CourseFilter
            sortBy={sortBy}
            courseType={courseType}
            offeringUnit={offeringUnit}
            offeringUnits={filterOptionsQuery.data?.offering_units || []}
            offeringUnitsLoading={filterOptionsQuery.isLoading}
            onSortChange={(value) => updateParams({ sort_by: value })}
            onCourseTypeChange={(value) => updateParams({ course_type: value })}
            onOfferingUnitChange={(value) => updateParams({ offering_unit: value })}
          />
          <CourseList courses={coursesQuery.data?.items} loading={coursesQuery.isLoading} />
          <Pagination
            className="pager"
            current={coursesQuery.data?.page || page}
            pageSize={coursesQuery.data?.per_page || 20}
            total={coursesQuery.data?.total || 0}
            showSizeChanger={false}
            onChange={(nextPage) => updateParams({ page: String(nextPage) })}
          />
        </Card>
      </div>
    </div>
  );
}
