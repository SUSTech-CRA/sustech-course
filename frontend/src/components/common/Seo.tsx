const SITE_NAME = 'Niuwa Curriculum Evaluation System';
const DEFAULT_DESCRIPTION = '南方科技大学（SUSTech）课程评价社区，浏览课程与教师点评，帮助同学找到更适合自己的课程。';

interface SeoProps {
  title: string;
  description?: string;
  noindex?: boolean;
  jsonLd?: Record<string, unknown> | Record<string, unknown>[];
}

// React 19 原生 metadata：title/meta 渲染在任意组件内都会被提升到 <head>。
// <title> 被插入 head 最前，优先于 index.html 的静态兜底 title 生效；
// meta 是追加式的，因此 index.html 不放静态 description，保证每页动态值唯一。
export function Seo({ title, description = DEFAULT_DESCRIPTION, noindex, jsonLd }: SeoProps) {
  const fullTitle = `${title} - ${SITE_NAME}`;
  return (
    <>
      <title>{fullTitle}</title>
      <meta name="description" content={description} />
      <meta property="og:site_name" content={SITE_NAME} />
      <meta property="og:title" content={fullTitle} />
      <meta property="og:description" content={description} />
      <meta property="og:type" content="website" />
      <meta name="twitter:card" content="summary" />
      {noindex && <meta name="robots" content="noindex, nofollow" />}
      {jsonLd && <script type="application/ld+json">{JSON.stringify(jsonLd)}</script>}
    </>
  );
}
