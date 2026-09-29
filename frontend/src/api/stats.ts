import apiClient from './client';
import type { RankingsResponse, SiteStatsResponse, StatsHistoryResponse } from '../types';

export const statsApi = {
  async site() {
    const { data } = await apiClient.get<SiteStatsResponse>('/stats');
    return data;
  },

  async rankings(limit = 50) {
    const { data } = await apiClient.get<RankingsResponse>('/stats/rankings', {
      params: { limit },
    });
    return data;
  },

  async history() {
    const { data } = await apiClient.get<StatsHistoryResponse>('/stats/history');
    return data;
  },
};

