import apiClient from './client';
import type { TeacherDetail, TeacherHistoryResponse, TeacherUpdate } from '../types';

export const teachersApi = {
  async detail(teacherId: number | string) {
    const { data } = await apiClient.get<TeacherDetail>(`/teacher/${teacherId}`);
    return data;
  },

  async update(teacherId: number | string, payload: TeacherUpdate) {
    const { data } = await apiClient.patch<TeacherDetail>(`/teacher/${teacherId}`, payload);
    return data;
  },

  async history(teacherId: number | string) {
    const { data } = await apiClient.get<TeacherHistoryResponse[]>(`/teacher/${teacherId}/history`);
    return data;
  },
};

