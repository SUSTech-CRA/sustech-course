import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { coursesApi } from '../api/courses';
import type { CourseListParams, CourseReviewParams } from '../types';

export function useCourses(params: CourseListParams) {
  return useQuery({
    queryKey: ['courses', params],
    queryFn: () => coursesApi.list(params),
    placeholderData: (previous) => previous,
  });
}

export function useCourseFilterOptions() {
  return useQuery({
    queryKey: ['course', 'filter-options'],
    queryFn: coursesApi.filterOptions,
    staleTime: 30 * 60 * 1000,
  });
}

export function useCourse(courseId?: number | string) {
  return useQuery({
    queryKey: ['course', courseId],
    queryFn: () => coursesApi.detail(courseId as number | string),
    enabled: Boolean(courseId),
  });
}

export function useCourseReviews(courseId?: number | string, params: CourseReviewParams = {}) {
  return useQuery({
    queryKey: ['course', courseId, 'reviews', params],
    queryFn: () => coursesApi.reviews(courseId as number | string, params),
    enabled: Boolean(courseId),
    placeholderData: (previous) => previous,
  });
}

export function useCourseStats(courseId?: number | string) {
  return useQuery({
    queryKey: ['course', courseId, 'stats'],
    queryFn: () => coursesApi.stats(courseId as number | string),
    enabled: Boolean(courseId),
  });
}

export function useCourseMutations(courseId?: number | string) {
  const queryClient = useQueryClient();
  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['course', courseId] });
    queryClient.invalidateQueries({ queryKey: ['courses'] });
  };

  return {
    upvote: useMutation({
      mutationFn: (enabled: boolean) => coursesApi.setUpvote(courseId as number | string, enabled),
      onSuccess: invalidate,
    }),
    downvote: useMutation({
      mutationFn: (enabled: boolean) =>
        coursesApi.setDownvote(courseId as number | string, enabled),
      onSuccess: invalidate,
    }),
    follow: useMutation({
      mutationFn: (enabled: boolean) => coursesApi.setFollow(courseId as number | string, enabled),
      onSuccess: invalidate,
    }),
    join: useMutation({
      mutationFn: (enabled: boolean) => coursesApi.setJoin(courseId as number | string, enabled),
      onSuccess: invalidate,
    }),
  };
}
