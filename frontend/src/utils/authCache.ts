import type { QueryClient } from '@tanstack/react-query';

import type { UserProfile, UserResponse } from '../types';

type AuthUser = UserResponse | UserProfile;

export function resetQueriesForAuthenticatedUser(queryClient: QueryClient, user: AuthUser) {
  // API responses such as review visibility and course actions vary by viewer.
  // Drop every pre-login/prior-user query before the destination page remounts.
  queryClient.removeQueries({
    predicate: (query) => query.queryKey[0] !== 'auth',
  });
  queryClient.setQueryData(['auth', 'me'], user);
}
