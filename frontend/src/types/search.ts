import type { PaginatedResponse } from './common';
import type { CourseBrief } from './course';
import type { ReviewResponse } from './review';
import type { TeacherBrief } from './user';

export type SearchType = 'all' | 'course' | 'review' | 'teacher';

export interface SearchResponse {
  courses: PaginatedResponse<CourseBrief> | null;
  reviews: PaginatedResponse<ReviewResponse> | null;
  teachers: PaginatedResponse<TeacherBrief> | null;
}

export interface SearchParams {
  q: string;
  type?: SearchType;
  page?: number;
  per_page?: number;
}

export interface SearchSuggestCourse {
  id: number;
  name: string;
  course_code?: string | null;
  teacher_names: string;
  review_count: number;
}

export interface SearchSuggestTeacher {
  id: number;
  name: string;
  title?: string | null;
}

export interface SearchSuggestResponse {
  courses: SearchSuggestCourse[];
  teachers: SearchSuggestTeacher[];
}

