import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect } from 'react';

import { authApi } from '../api/auth';
import { useAuthStore } from '../stores/authStore';
import type { LoginRequest, RegisterRequest } from '../types';
import { resetQueriesForAuthenticatedUser } from '../utils/authCache';

export function useAuth() {
  const auth = useAuthStore();
  const queryClient = useQueryClient();

  const meQuery = useQuery({
    queryKey: ['auth', 'me'],
    queryFn: authApi.me,
    enabled: Boolean(auth.accessToken),
    retry: false,
  });

  useEffect(() => {
    if (meQuery.data) {
      useAuthStore.getState().setUser(meQuery.data);
    }
  }, [meQuery.data]);

  const loginMutation = useMutation({
    mutationFn: async (payload: LoginRequest) => {
      const tokens = await authApi.login(payload);
      useAuthStore.getState().setTokens(tokens.access_token, tokens.refresh_token);
      const user = await authApi.me();
      useAuthStore.getState().login(user, tokens.access_token, tokens.refresh_token);
      return user;
    },
    onSuccess: (user) => {
      resetQueriesForAuthenticatedUser(queryClient, user);
    },
  });

  const registerMutation = useMutation({
    mutationFn: (payload: RegisterRequest) => authApi.register(payload),
  });

  const logoutMutation = useMutation({
    mutationFn: async () => {
      const refreshToken = useAuthStore.getState().refreshToken;
      useAuthStore.getState().logout();
      queryClient.removeQueries();
      if (refreshToken) {
        await authApi.logout(refreshToken).catch(() => undefined);
      }
    },
  });

  return {
    ...auth,
    meQuery,
    loginMutation,
    registerMutation,
    logoutMutation,
  };
}
