import type { CourseBrief } from './course';
import type { UserBrief } from './user';

export type ReviewSortBy =
  | 'upvote'
  | 'updatetime_desc'
  | 'pubtime_desc'
  | 'pubtime'
  | 'score_desc'
  | 'score';
export type ReviewFeedFilter = 'latest' | 'following' | 'following_users';

export interface ReviewCreate {
  course_id: number;
  term: string;
  difficulty: number;
  homework: number;
  grading: number;
  gain: number;
  rate: number;
  content: string;
  is_anonymous: boolean;
  only_visible_to_student: boolean;
}

export interface ReviewUpdate {
  term?: string;
  difficulty?: number;
  homework?: number;
  grading?: number;
  gain?: number;
  rate?: number;
  content?: string;
  is_anonymous?: boolean;
  only_visible_to_student?: boolean;
}

export interface ReviewResponse {
  id: number;
  difficulty: number;
  homework: number;
  grading: number;
  gain: number;
  rate: number;
  content: string;
  publish_time?: string | null;
  update_time?: string | null;
  upvote_count: number;
  comment_count: number;
  is_anonymous: boolean;
  only_visible_to_student: boolean;
  is_hidden: boolean;
  is_blocked: boolean;
  term: string;
  author?: UserBrief | null;
  course?: CourseBrief | null;
  difficulty_display: string;
  homework_display: string;
  grading_display: string;
  gain_display: string;
  term_display: string;
  is_upvoted: boolean;
  /** 仅搜索结果填充：服务端已转义、只含 <mark> 高亮标签的纯文本摘要 */
  content_snippet?: string | null;
}

export interface ReviewListParams {
  page?: number;
  per_page?: number;
  sort_by?: ReviewSortBy;
  filter?: ReviewFeedFilter;
}

export interface CourseReviewParams {
  page?: number;
  per_page?: number;
  sort_by?: ReviewSortBy;
  term?: string;
  rating?: number;
}

export interface CommentCreate {
  content: string;
}

export interface CommentResponse {
  id: number;
  review_id?: number | null;
  author_id?: number | null;
  content: string;
  publish_time?: string | null;
  author?: UserBrief | null;
}

