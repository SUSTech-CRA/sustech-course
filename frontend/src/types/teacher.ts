import type { CourseBrief } from './course';
import type { TeacherBrief } from './user';

export interface TeacherDetail extends TeacherBrief {
  dept_id?: number | null;
  office_phone?: string | null;
  gender?: string | null;
  description?: string | null;
  homepage?: string | null;
  research_interest?: string | null;
  access_count?: number | null;
  image_locked: boolean;
  info_locked: boolean;
  courses: CourseBrief[];
  review_count: number;
  average_rate: number;
  normalized_rate: number;
}

export interface TeacherUpdate {
  description?: string | null;
  homepage?: string | null;
  research_interest?: string | null;
  office_phone?: string | null;
  image?: string | null;
  info_locked?: boolean;
  image_locked?: boolean;
}

export interface TeacherHistoryResponse {
  id: number;
  author?: number | null;
  update_time?: string | null;
  image?: string | null;
  homepage?: string | null;
  description?: string | null;
  research_interest?: string | null;
}
