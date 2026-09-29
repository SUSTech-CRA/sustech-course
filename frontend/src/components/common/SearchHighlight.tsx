import DOMPurify from 'dompurify';

interface SearchHighlightProps {
  /** 服务端已转义、只含 <mark> 标签的高亮文本（搜索结果专用） */
  html: string;
  className?: string;
}

/** 渲染搜索高亮片段：DOMPurify 兜底，只放行 <mark>，其余一律转义为文本。 */
export function SearchHighlight({ html, className }: SearchHighlightProps) {
  const clean = DOMPurify.sanitize(html, { ALLOWED_TAGS: ['mark'], ALLOWED_ATTR: [] });
  return <span className={className} dangerouslySetInnerHTML={{ __html: clean }} />;
}
