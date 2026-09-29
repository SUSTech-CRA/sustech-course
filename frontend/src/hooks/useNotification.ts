import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { usersApi } from '../api/users';
import { useAuthStore } from '../stores/authStore';

export function useNotifications(page = 1, perPage = 20) {
  return useQuery({
    queryKey: ['notifications', page, perPage],
    queryFn: () => usersApi.notifications({ page, per_page: perPage }),
  });
}

export function useReadNotificationsMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: usersApi.markNotificationsRead,
    onSuccess: () => {
      const { user, setUser } = useAuthStore.getState();
      if (user) {
        setUser({ ...user, unread_notification_count: 0 });
        queryClient.setQueryData(['auth', 'me'], { ...user, unread_notification_count: 0 });
      }
      queryClient.invalidateQueries({ queryKey: ['notifications'] });
      queryClient.invalidateQueries({ queryKey: ['auth'] });
    },
  });
}
