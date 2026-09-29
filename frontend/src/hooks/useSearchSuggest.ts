import { useQuery } from '@tanstack/react-query';
import { useEffect, useState } from 'react';

import { searchApi } from '../api/search';

const DEBOUNCE_MS = 200;

/** 导航栏即时搜索建议：输入 debounce 后请求 /search/suggest（课程 + 教师）。 */
export function useSearchSuggest(keyword: string) {
  const [debounced, setDebounced] = useState(keyword);

  useEffect(() => {
    const timer = window.setTimeout(() => setDebounced(keyword), DEBOUNCE_MS);
    return () => window.clearTimeout(timer);
  }, [keyword]);

  const q = debounced.trim();
  return useQuery({
    queryKey: ['search-suggest', q],
    queryFn: () => searchApi.suggest(q),
    enabled: q.length > 0,
    staleTime: 60 * 1000,
    placeholderData: (previous) => previous,
  });
}
