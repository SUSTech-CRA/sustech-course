import type { TeacherBrief } from './user';

export type CourseSortBy =
  | 'rate'
  | 'rate_asc'
  | 'review_count'
  | 'upvote'
  | 'follow'
  | 'join'
  | 'name';

export interface CourseRateBrief {
  review_count: number;
  upvote_count: number;
  downvote_count: number;
  follow_count: number;
  join_count: number;
  rate_average?: number | null;
  average_rate?: number | null;
  difficulty?: string | null;
  homework?: string | null;
  grading?: string | null;
  gain?: string | null;
  difficulty_score?: string | null;
  homework_score?: string | null;
  grading_score?: string | null;
  gain_score?: string | null;
}

export interface CourseBrief {
  id: number;
  name: string;
  course_code?: string | null;
  teacher_names: string;
  term_ids: string[];
  review_count: number;
  rate_average?: number | null;
  difficulty_score?: string | null;
  homework_score?: string | null;
  grading_score?: string | null;
  gain_score?: string | null;
  /** 仅搜索结果填充：服务端已转义、只含 <mark> 高亮标签的课名 */
  name_highlighted?: string | null;
}

export interface CourseFilterOptions {
  offering_units: string[];
}

export interface TeacherCourseGroup {
  teacher: TeacherBrief;
  courses: CourseBrief[];
}

export interface CourseTermResponse {
  id: number;
  term?: string | null;
  courseries?: string | null;
  kcid?: string | null;
  course_major?: string | null;
  course_type?: string | null;
  course_level?: string | null;
  join_type?: string | null;
  teaching_type?: string | null;
  grading_type?: string | null;
  credit?: number | null;
  hours?: number | null;
  hours_per_week?: number | null;
  campus?: string | null;
  start_week?: number | null;
  end_week?: number | null;
}

export interface CourseReviewSummary {
  overview: string;
  strengths: string[];
  caveats: string[];
  assessment: string[];
  source_review_count: number;
  generated_at: string;
}

export interface CourseDetail {
  id: number;
  name: string;
  course_code?: string | null;
  courseries?: string | null;
  course_material_code?: string | null;
  dept?: string | null;
  introduction?: string | null;
  homepage?: string | null;
  admin_announcement?: string | null;
  latest_score?: string | null;
  access_count?: number | null;
  teachers: TeacherBrief[];
  credit?: number | null;
  hours?: number | null;
  hours_per_week?: number | null;
  description?: string | null;
  description_eng?: string | null;
  teaching_material?: string | null;
  reference_material?: string | null;
  student_requirements?: string | null;
  campus?: string | null;
  course_major?: string | null;
  course_type?: string | null;
  grading_type?: string | null;
  rate?: CourseRateBrief | null;
  review_term_list: string[];
  terms: CourseTermResponse[];
  related_courses: CourseBrief[];
  same_teacher_courses: TeacherCourseGroup[];
  is_upvoted: boolean;
  is_downvoted: boolean;
  is_following: boolean;
  is_joined: boolean;
  has_reviewed: boolean;
  num_blocked_reviews: number;
  num_deleted_reviews: number;
  ai_summary?: CourseReviewSummary | null;
}

export interface CourseTermStat {
  term: string;
  review_count: number;
  rate_average?: number | null;
}

export interface CourseStats {
  course_id: number;
  review_count: number;
  rating_distribution: Record<string, number>;
  term_distribution: Record<string, number>;
  term_stats: CourseTermStat[];
}

export interface CourseUpdate {
  name?: string;
  course_code?: string | null;
  dept_id?: number | null;
  introduction?: string | null;
  homepage?: string | null;
  admin_announcement?: string | null;
  teacher_ids?: number[];
}

export interface CourseHistoryResponse {
  id: number;
  author?: number | null;
  update_time?: string | null;
  introduction?: string | null;
  homepage?: string | null;
}

export interface CourseMaterialEntry {
  name: string;
  path: string;
  key: string;
  is_dir: boolean;
  size?: number | null;
  last_modified?: string | null;
  content_type?: string | null;
}

export interface CourseMaterialListResponse {
  course_id: number;
  base_code: string;
  prefix: string;
  path: string;
  directories: CourseMaterialEntry[];
  files: CourseMaterialEntry[];
}

export interface CourseListParams {
  page?: number;
  per_page?: number;
  sort_by?: CourseSortBy;
  course_type?: string;
  offering_unit?: string;
}
