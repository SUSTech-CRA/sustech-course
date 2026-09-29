import apiClient from './client';
import type {
  CommentCreate,
  CommentResponse,
  MessageResponse,
  PaginatedResponse,
  ReviewCreate,
  ReviewListParams,
  ReviewResponse,
  ReviewUpdate,
} from '../types';

export const reviewsApi = {
  async list(params: ReviewListParams = {}) {
    const { data } = await apiClient.get<PaginatedResponse<ReviewResponse>>('/review', { params });
    return data;
  },

  async detail(reviewId: number | string) {
    const { data } = await apiClient.get<ReviewResponse>(`/review/${reviewId}`);
    return data;
  },

  async create(payload: ReviewCreate) {
    const { data } = await apiClient.post<ReviewResponse>('/review', payload);
    return data;
  },

  async update(reviewId: number | string, payload: ReviewUpdate) {
    const { data } = await apiClient.patch<ReviewResponse>(`/review/${reviewId}`, payload);
    return data;
  },

  async remove(reviewId: number | string) {
    const { data } = await apiClient.delete<MessageResponse>(`/review/${reviewId}`);
    return data;
  },

  async setUpvote(reviewId: number | string, enabled: boolean) {
    const { data } = await apiClient<ReviewResponse>({
      method: enabled ? 'post' : 'delete',
      url: `/review/${reviewId}/upvote`,
    });
    return data;
  },

  async comments(reviewId: number | string) {
    const { data } = await apiClient.get<CommentResponse[]>(`/review/${reviewId}/comments`);
    return data;
  },

  async addComment(reviewId: number | string, payload: CommentCreate) {
    const { data } = await apiClient.post<CommentResponse>(
      `/review/${reviewId}/comments`,
      payload,
    );
    return data;
  },

  async deleteComment(commentId: number | string) {
    const { data } = await apiClient.delete<MessageResponse>(`/review/comments/${commentId}`);
    return data;
  },

  async setHidden(reviewId: number | string, hidden: boolean) {
    const { data } = await apiClient.post<ReviewResponse>(
      `/review/${reviewId}/${hidden ? 'hide' : 'unhide'}`,
    );
    return data;
  },

  async setBlocked(reviewId: number | string, blocked: boolean) {
    const { data } = await apiClient.post<ReviewResponse>(
      `/review/${reviewId}/${blocked ? 'block' : 'unblock'}`,
    );
    return data;
  },
};
