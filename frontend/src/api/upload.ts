import apiClient from './client';
import type { UploadResponse } from '../types';

export const uploadApi = {
  async image(file: File) {
    const formData = new FormData();
    formData.append('file', file);
    const { data } = await apiClient.post<UploadResponse>('/upload/image', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return data;
  },
  async file(file: File) {
    const formData = new FormData();
    formData.append('file', file);
    const { data } = await apiClient.post<UploadResponse>('/upload/file', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return data;
  },
};
