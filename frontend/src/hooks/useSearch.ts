import { useQuery } from '@tanstack/react-query';

import { searchApi } from '../api/search';
import type { SearchParams } from '../types';

export function useSearch(params: SearchParams, enabled = true) {
  return useQuery({
    queryKey: ['search', params],
    queryFn: () => searchApi.search(params),
    enabled: enabled && params.q.trim().length > 0,
    placeholderData: (previous) => previous,
  });
}
