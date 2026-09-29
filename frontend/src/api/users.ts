import apiClient from './client';
import type {
  BindStudentRequest,
  CourseBrief,
  NotificationResponse,
  PaginatedResponse,
  ReviewResponse,
  UserBrief,
  UserProfile,
  UserUpdate,
} from '../types';

export const usersApi = {
  async profile(userId: number | string) {
    const { data } = await apiClient.get<UserProfile>(`/user/${userId}`);
    return data;
  },

  async updateMe(payload: UserUpdate) {
    const { data } = await apiClient.patch<UserProfile>('/user/me', payload);
    return data;
  },

  async bindStudent(payload: BindStudentRequest) {
    const { data } = await apiClient.post<UserProfile>('/user/me/bind-student', payload);
    return data;
  },

  async reviews(userId: number | string, params: { page?: number; per_page?: number } = {}) {
    const { data } = await apiClient.get<PaginatedResponse<ReviewResponse>>(
      `/user/${userId}/reviews`,
      { params },
    );
    return data;
  },

  async followingCourses(
    userId: number | string,
    params: { page?: number; per_page?: number } = {},
  ) {
    const { data } = await apiClient.get<PaginatedResponse<CourseBrief>>(
      `/user/${userId}/following-courses`,
      { params },
    );
    return data;
  },

  async joinedCourses(userId: number | string, params: { page?: number; per_page?: number } = {}) {
    const { data } = await apiClient.get<PaginatedResponse<CourseBrief>>(
      `/user/${userId}/joined-courses`,
      { params },
    );
    return data;
  },

  async followers(userId: number | string, params: { page?: number; per_page?: number } = {}) {
    const { data } = await apiClient.get<PaginatedResponse<UserBrief>>(
      `/user/${userId}/followers`,
      { params },
    );
    return data;
  },

  async followings(userId: number | string, params: { page?: number; per_page?: number } = {}) {
    const { data } = await apiClient.get<PaginatedResponse<UserBrief>>(
      `/user/${userId}/followings`,
      { params },
    );
    return data;
  },

  async setFollow(userId: number | string, enabled: boolean) {
    const { data } = await apiClient<UserProfile>({
      method: enabled ? 'post' : 'delete',
      url: `/user/${userId}/follow`,
    });
    return data;
  },

  async notifications(params: { page?: number; per_page?: number } = {}) {
    const { data } = await apiClient.get<PaginatedResponse<NotificationResponse>>(
      '/user/me/notifications',
      { params },
    );
    return data;
  },

  async markNotificationsRead() {
    await apiClient.post('/user/me/notifications/read-all');
  },
};
