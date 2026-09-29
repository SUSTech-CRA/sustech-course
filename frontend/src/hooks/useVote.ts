import { useCourseMutations } from './useCourse';
import { useReviewMutations } from './useReview';

export function useCourseVote(courseId?: number | string) {
  return useCourseMutations(courseId);
}

export function useReviewVote() {
  return useReviewMutations().upvote;
}

