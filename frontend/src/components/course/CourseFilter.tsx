import { Select, Typography } from 'antd';

import type { CourseSortBy } from '../../types';
import { COURSE_SORT_OPTIONS, COURSE_TYPE_OPTIONS } from '../../utils/constants';

interface CourseFilterProps {
  sortBy: CourseSortBy;
  courseType?: string;
  offeringUnit?: string;
  offeringUnits: string[];
  offeringUnitsLoading?: boolean;
  onSortChange: (value: CourseSortBy) => void;
  onCourseTypeChange: (value?: string) => void;
  onOfferingUnitChange: (value?: string) => void;
}

export function CourseFilter({
  sortBy,
  courseType,
  offeringUnit,
  offeringUnits,
  offeringUnitsLoading,
  onSortChange,
  onCourseTypeChange,
  onOfferingUnitChange,
}: CourseFilterProps) {
  return (
    <div className="course-filter">
      <div className="course-filter-field">
        <Typography.Text strong>排序</Typography.Text>
        <Select
          aria-label="课程排序"
          value={sortBy}
          options={COURSE_SORT_OPTIONS}
          onChange={onSortChange}
        />
      </div>
      <div className="course-filter-field">
        <Typography.Text strong>课程类别</Typography.Text>
        <Select
          aria-label="课程类别"
          allowClear
          placeholder="全部"
          value={courseType}
          options={COURSE_TYPE_OPTIONS}
          onChange={onCourseTypeChange}
        />
      </div>
      <div className="course-filter-field">
        <Typography.Text strong>开课单位</Typography.Text>
        <Select
          aria-label="开课单位"
          allowClear
          showSearch
          optionFilterProp="label"
          placeholder="全部"
          value={offeringUnit}
          loading={offeringUnitsLoading}
          options={offeringUnits.map((value) => ({ label: value, value }))}
          onChange={onOfferingUnitChange}
        />
      </div>
    </div>
  );
}
