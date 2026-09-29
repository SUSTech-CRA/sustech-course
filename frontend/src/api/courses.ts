import apiClient, { API_BASE_URL } from './client';
import type {
  CourseBrief,
  CourseDetail,
  CourseFilterOptions,
  CourseHistoryResponse,
  CourseListParams,
  CourseMaterialListResponse,
  CourseReviewParams,
  CourseStats,
  CourseUpdate,
  PaginatedResponse,
  ReviewResponse,
} from '../types';

export const coursesApi = {
  async list(params: CourseListParams = {}) {
    const { data } = await apiClient.get<PaginatedResponse<CourseBrief>>('/course', { params });
    return data;
  },

  async filterOptions() {
    const { data } = await apiClient.get<CourseFilterOptions>('/course/filter-options');
    return data;
  },

  async detail(courseId: number | string) {
    const { data } = await apiClient.get<CourseDetail>(`/course/${courseId}`);
    return data;
  },

  async update(courseId: number | string, payload: CourseUpdate) {
    const { data } = await apiClient.patch<CourseDetail>(`/course/${courseId}`, payload);
    return data;
  },

  async reviews(courseId: number | string, params: CourseReviewParams = {}) {
    const { data } = await apiClient.get<PaginatedResponse<ReviewResponse>>(
      `/course/${courseId}/reviews`,
      { params },
    );
    return data;
  },

  async stats(courseId: number | string) {
    const { data } = await apiClient.get<CourseStats>(`/course/${courseId}/stats`);
    return data;
  },

  async history(courseId: number | string) {
    const { data } = await apiClient.get<CourseHistoryResponse[]>(`/course/${courseId}/history`);
    return data;
  },

  async lookupByCode(cno: string, term?: number) {
    const { data } = await apiClient.get<{ course_id: number }>(`/course/by-code/${encodeURIComponent(cno)}`, {
      params: term ? { term } : undefined,
    });
    return data.course_id;
  },

  async materials(courseId: number | string, path?: string) {
    const { data } = await apiClient.get<CourseMaterialListResponse>(
      `/course/${courseId}/materials`,
      { params: { path } },
    );
    return data;
  },

  async materialPresignUrl(courseId: number | string, path: string) {
    const { data } = await apiClient.get<{ url: string }>(
      `/course/${courseId}/materials/presign`,
      { params: { path } },
    );
    return data.url;
  },

  materialDownloadUrl(courseId: number | string, path: string) {
    const params = new URLSearchParams({ path });
    return `${API_BASE_URL}/course/${courseId}/materials/download?${params.toString()}`;
  },

  async setUpvote(courseId: number | string, enabled: boolean) {
    const { data } = await apiClient<CourseDetail>({
      method: enabled ? 'post' : 'delete',
      url: `/course/${courseId}/upvote`,
    });
    return data;
  },

  async setDownvote(courseId: number | string, enabled: boolean) {
    const { data } = await apiClient<CourseDetail>({
      method: enabled ? 'post' : 'delete',
      url: `/course/${courseId}/downvote`,
    });
    return data;
  },

  async setFollow(courseId: number | string, enabled: boolean) {
    const { data } = await apiClient<CourseDetail>({
      method: enabled ? 'post' : 'delete',
      url: `/course/${courseId}/follow`,
    });
    return data;
  },

  async setJoin(courseId: number | string, enabled: boolean) {
    const { data } = await apiClient<CourseDetail>({
      method: enabled ? 'post' : 'delete',
      url: `/course/${courseId}/join`,
    });
    return data;
  },

  async addTeacher(courseId: number | string, teacherId: number) {
    const { data } = await apiClient.post<CourseDetail>(`/course/${courseId}/teachers`, {
      teacher_id: teacherId,
    });
    return data;
  },

  async removeTeacher(courseId: number | string, teacherId: number) {
    const { data } = await apiClient.delete<CourseDetail>(`/course/${courseId}/teachers/${teacherId}`);
    return data;
  },
};
