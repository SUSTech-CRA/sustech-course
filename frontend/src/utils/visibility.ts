import type { ReviewResponse } from '../types';

type CurrentUser = {
  id: number;
  role?: string | null;
  identity?: string | null;
};

export function reviewVisibilityTags(review: ReviewResponse) {
  const tags: string[] = [];
  if (review.only_visible_to_student) tags.push('仅学生可见');
  if (review.is_hidden) tags.push('已隐藏');
  if (review.is_blocked) tags.push('已屏蔽');
  if (review.is_anonymous) tags.push('匿名');
  return tags;
}

export function canEditReview(review: ReviewResponse, user?: CurrentUser | null) {
  if (!user || !review.author) return false;
  return user.role === 'Admin' || user.id === review.author.id;
}

export function isStudent(user?: CurrentUser | null) {
  return user?.identity === 'Student';
}

export function isAdmin(user?: CurrentUser | null) {
  return user?.role === 'Admin';
}
