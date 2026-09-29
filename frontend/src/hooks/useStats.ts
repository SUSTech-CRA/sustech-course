import { useQuery } from '@tanstack/react-query';

import { statsApi } from '../api/stats';

export function useSiteStats() {
  return useQuery({
    queryKey: ['stats', 'site'],
    queryFn: statsApi.site,
  });
}

export function useRankings(limit = 50) {
  return useQuery({
    queryKey: ['stats', 'rankings', limit],
    queryFn: () => statsApi.rankings(limit),
  });
}

export function useStatsHistory() {
  return useQuery({
    queryKey: ['stats', 'history'],
    queryFn: statsApi.history,
  });
}
