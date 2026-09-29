import type { CourseSortBy, ReviewSortBy, SelectOption } from '../types';

export const COURSE_SORT_OPTIONS: SelectOption<CourseSortBy>[] = [
  { label: '综合评分', value: 'rate' },
  { label: '评分从低到高', value: 'rate_asc' },
  { label: '点评最多', value: 'review_count' },
  { label: '推荐最多', value: 'upvote' },
  { label: '关注最多', value: 'follow' },
  { label: '学过最多', value: 'join' },
  { label: '课程名', value: 'name' },
];

export const REVIEW_SORT_OPTIONS: SelectOption<ReviewSortBy>[] = [
  { label: '赞同最多', value: 'upvote' },
  { label: '最新更新', value: 'updatetime_desc' },
  { label: '最新发布', value: 'pubtime_desc' },
  { label: '最早发布', value: 'pubtime' },
  { label: '评分最高', value: 'score_desc' },
  { label: '评分最低', value: 'score' },
];

// 与老版 course_type_dict 一致的分组 key，后端按组内多个类别值 + join_type 匹配
export const COURSE_TYPE_OPTIONS = [
  { label: '公选课', value: 'public' },
  { label: '公共课（英语，思政）', value: 'general' },
  { label: '通识课', value: 'general-sci' },
  { label: '专业课', value: 'major' },
  { label: '实践与毕业论文', value: 'practice-and-graduate' },
];

// 注意：grading 1=超好、gain 1=很多，数值方向与直觉相反，
// 必须使用与老版一致的语义标签，不能用统一的"低/中/高"。
export const DIMENSION_FIELD_OPTIONS: Record<
  'difficulty' | 'homework' | 'grading' | 'gain',
  SelectOption<number>[]
> = {
  difficulty: [
    { value: 1, label: '简单' },
    { value: 2, label: '中等' },
    { value: 3, label: '困难' },
  ],
  homework: [
    { value: 1, label: '不多' },
    { value: 2, label: '中等' },
    { value: 3, label: '超多' },
  ],
  grading: [
    { value: 1, label: '超好' },
    { value: 2, label: '一般' },
    { value: 3, label: '杀手' },
  ],
  gain: [
    { value: 1, label: '很多' },
    { value: 2, label: '一般' },
    { value: 3, label: '没有' },
  ],
};

export const FALLBACK_AVATAR = '/avatar-placeholder.svg';
export const FALLBACK_TEACHER_IMAGE = '/teacher-placeholder.svg';

