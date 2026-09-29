import apiClient from './client';
import type { RequestInfoResponse } from '../types';

export const metaApi = {
  async requestInfo() {
    const { data } = await apiClient.get<RequestInfoResponse>('/meta/request-info');
    return data;
  },
};
