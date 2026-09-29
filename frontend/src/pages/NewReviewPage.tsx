import { App as AntApp, Button, Result, Spin } from 'antd';
import { Link, useLocation, useNavigate, useParams } from 'react-router-dom';

import { getApiErrorMessage } from '../api/client';
import { PageTitle } from '../components/common/PageTitle';
import { Seo } from '../components/common/Seo';
import { ReviewForm } from '../components/review/ReviewForm';
import { useCourse } from '../hooks/useCourse';
import { useReview, useReviewMutations } from '../hooks/useReview';
import { useAuthStore } from '../stores/authStore';
import type { ReviewCreate, ReviewUpdate } from '../types';
import { buildSignInPath, getRedirectFromLocation } from '../utils/authRedirect';

export function NewReviewPage() {
  const { id, reviewId } = useParams();
  const location = useLocation();
  const navigate = useNavigate();
  const { message } = AntApp.useApp();
  const user = useAuthStore((state) => state.user);
  const reviewQuery = useReview(reviewId);
  const courseId = id || reviewQuery.data?.course?.id;
  const courseQuery = useCourse(courseId);
  const { create, update } = useReviewMutations();
  const signInPath = buildSignInPath(getRedirectFromLocation(location));

  if (!user) {
    return (
      <Result
        status="403"
        title="请先登录"
        subTitle="登录后才能发布或编辑课程点评。"
        extra={
          <Button type="primary" href={signInPath}>
            去登录
          </Button>
        }
      />
    );
  }

  if (courseQuery.isLoading || (reviewId && reviewQuery.isLoading)) {
    return <Spin fullscreen description="加载点评表单" />;
  }

  if (!courseQuery.data) {
    return <Result status="404" title="课程不存在或无法访问" />;
  }

  const submit = async (payload: ReviewCreate | ReviewUpdate) => {
    try {
      const review = reviewId
        ? await update.mutateAsync({ reviewId, payload: payload as ReviewUpdate })
        : await create.mutateAsync(payload as ReviewCreate);
      message.success(reviewId ? '点评已更新' : '点评已发布');
      navigate(`/course/${review.course?.id || courseQuery.data.id}#review-${review.id}`);
    } catch (error) {
      message.error(getApiErrorMessage(error, '提交点评失败'));
    }
  };

  return (
    <div>
      <Seo title={reviewId ? '编辑点评' : '写点评'} noindex />
      <PageTitle
        title={reviewId ? '编辑点评' : '写点评'}
        subtitle={
          <>
            课程：<Link to={`/course/${courseQuery.data.id}`}>{courseQuery.data.name}</Link>
          </>
        }
      />
      <ReviewForm
        course={courseQuery.data}
        initialReview={reviewQuery.data}
        onSubmit={submit}
        loading={create.isPending || update.isPending}
      />
    </div>
  );
}
