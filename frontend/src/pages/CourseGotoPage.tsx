import { Result, Spin } from 'antd';
import { useEffect, useRef, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';

import { coursesApi } from '../api/courses';
import { Seo } from '../components/common/Seo';

export function CourseGotoPage() {
  const { cno, term } = useParams();
  const navigate = useNavigate();
  const handledRef = useRef(false);
  const [error, setError] = useState(false);

  useEffect(() => {
    if (handledRef.current || !cno) return;
    handledRef.current = true;
    coursesApi
      .lookupByCode(cno, term ? Number(term) : undefined)
      .then((courseId) => navigate(`/course/${courseId}`, { replace: true }))
      .catch(() => setError(true));
  }, [cno, term, navigate]);

  if (error) {
    return (
      <>
        <Seo title="课程不存在" noindex />
        <Result status="404" title="课程不存在" subTitle={`未找到课程号「${cno}」对应的课程`} />
      </>
    );
  }

  return (
    <>
      <Seo title="正在定位课程" noindex />
      <Spin fullscreen description="正在定位课程" />
    </>
  );
}
