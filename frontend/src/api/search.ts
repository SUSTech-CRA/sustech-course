import apiClient from './client';
import type { SearchParams, SearchResponse, SearchSuggestResponse } from '../types';

export const searchApi = {
  async search(params: SearchParams) {
    const { data } = await apiClient.get<SearchResponse>('/search', { params });
    return data;
  },
  async suggest(q: string) {
    const { data } = await apiClient.get<SearchSuggestResponse>('/search/suggest', { params: { q } });
    return data;
  },
};
