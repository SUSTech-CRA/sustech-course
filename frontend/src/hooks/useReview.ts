import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { reviewsApi } from '../api/reviews';
import type { ReviewCreate, ReviewListParams, ReviewUpdate } from '../types';

export function useReviews(params: ReviewListParams) {
  return useQuery({
    queryKey: ['reviews', params],
    queryFn: () => reviewsApi.list(params),
    placeholderData: (previous) => previous,
  });
}

export function useReview(reviewId?: number | string) {
  return useQuery({
    queryKey: ['review', reviewId],
    queryFn: () => reviewsApi.detail(reviewId as number | string),
    enabled: Boolean(reviewId),
  });
}

export function useReviewMutations() {
  const queryClient = useQueryClient();

  return {
    create: useMutation({
      mutationFn: (payload: ReviewCreate) => reviewsApi.create(payload),
      onSuccess: (review) => {
        invalidateReviewQueries(queryClient, review.course?.id);
      },
    }),
    update: useMutation({
      mutationFn: ({ reviewId, payload }: { reviewId: number | string; payload: ReviewUpdate }) =>
        reviewsApi.update(reviewId, payload),
      onSuccess: (review) => {
        queryClient.invalidateQueries({ queryKey: ['review', review.id] });
        invalidateReviewQueries(queryClient, review.course?.id);
      },
    }),
    remove: useMutation({
      mutationFn: (reviewId: number | string) => reviewsApi.remove(reviewId),
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: ['reviews'] });
        queryClient.invalidateQueries({ queryKey: ['course'] });
      },
    }),
    upvote: useMutation({
      mutationFn: ({ reviewId, enabled }: { reviewId: number | string; enabled: boolean }) =>
        reviewsApi.setUpvote(reviewId, enabled),
      onSuccess: (review) => {
        queryClient.invalidateQueries({ queryKey: ['review', review.id] });
        invalidateReviewQueries(queryClient, review.course?.id);
      },
    }),
    setHidden: useMutation({
      mutationFn: ({ reviewId, hidden }: { reviewId: number | string; hidden: boolean }) =>
        reviewsApi.setHidden(reviewId, hidden),
      onSuccess: (review) => {
        queryClient.invalidateQueries({ queryKey: ['review', review.id] });
        invalidateReviewQueries(queryClient, review.course?.id);
      },
    }),
    setBlocked: useMutation({
      mutationFn: ({ reviewId, blocked }: { reviewId: number | string; blocked: boolean }) =>
        reviewsApi.setBlocked(reviewId, blocked),
      onSuccess: (review) => {
        queryClient.invalidateQueries({ queryKey: ['review', review.id] });
        invalidateReviewQueries(queryClient, review.course?.id);
      },
    }),
  };
}

export function useReviewComments(reviewId?: number | string, enabled = false) {
  return useQuery({
    queryKey: ['review', reviewId, 'comments'],
    queryFn: () => reviewsApi.comments(reviewId as number | string),
    enabled: Boolean(reviewId) && enabled,
  });
}

export function useCommentMutation(reviewId: number | string) {
  const queryClient = useQueryClient();
  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['review', reviewId, 'comments'] });
    queryClient.invalidateQueries({ queryKey: ['reviews'] });
    queryClient.invalidateQueries({ queryKey: ['course'] });
  };

  return {
    add: useMutation({
      mutationFn: (content: string) => reviewsApi.addComment(reviewId, { content }),
      onSuccess: invalidate,
    }),
    remove: useMutation({
      mutationFn: (commentId: number | string) => reviewsApi.deleteComment(commentId),
      onSuccess: invalidate,
    }),
  };
}

export function invalidateReviewQueries(queryClient: ReturnType<typeof useQueryClient>, courseId?: number | string) {
  queryClient.invalidateQueries({ queryKey: ['reviews'] });
  queryClient.invalidateQueries({ queryKey: ['course'] });
  if (courseId !== undefined && courseId !== null) {
    queryClient.invalidateQueries({ queryKey: ['course', String(courseId)] });
    queryClient.invalidateQueries({ queryKey: ['course', String(courseId), 'reviews'] });
    queryClient.invalidateQueries({ queryKey: ['course', Number(courseId)] });
    queryClient.invalidateQueries({ queryKey: ['course', Number(courseId), 'reviews'] });
  }
}
