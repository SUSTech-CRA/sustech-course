import type { CourseBrief } from './course';
import type { UserBrief } from './user';

export interface SiteStatsResponse {
  user_count: number;
  course_count: number;
  review_count: number;
  teacher_count: number;
  registered_teacher_count: number;
  running_days: number;
  course_avg_rate?: number | null;
  course_avg_rate_count?: number | null;
  review_rate_distribution: DistributionPoint[];
  course_rate_distribution: DistributionPoint[];
  course_review_count_distribution: SeriesPoint[];
  user_review_count_distribution: SeriesPoint[];
  review_monthly_distribution: SeriesPoint[];
  user_monthly_distribution: SeriesPoint[];
}

export interface DistributionPoint {
  label: string;
  value: number;
}

export interface SeriesPoint {
  label: string;
  value: number;
  cumulative?: number | null;
}

export interface RankingsStats {
  avg_rate: number;
  avg_rate_count: number;
  avg_review_upvotes: number;
  avg_review_length: number;
}

export interface CourseRankingItem extends CourseBrief {
  normalized_rate?: number | null;
}

export interface TeacherRankingItem {
  id: number;
  name?: string | null;
  dept?: string | null;
  course_count: number;
  review_count: number;
  normalized_rate?: number | null;
}

export interface ReviewRankingItem {
  course_id: number;
  course_name: string;
  review_id: number;
  author?: UserBrief | null;
  author_name: string;
  is_anonymous: boolean;
  upvote_count: number;
  content_length?: number | null;
}

export interface UserRankingItem {
  user: UserBrief;
  reviews_count: number;
  review_upvotes_count: number;
  review_length: number;
  score: number;
}

export interface RankingsResponse {
  stats: RankingsStats;
  top_teachers: TeacherRankingItem[];
  top_rated_courses: CourseRankingItem[];
  popular_courses: CourseRankingItem[];
  top_reviews: ReviewRankingItem[];
  long_reviews: ReviewRankingItem[];
  top_users: UserRankingItem[];
}

export interface StatsHistoryResponse {
  site: SiteStatsResponse;
  rankings: RankingsResponse;
}
