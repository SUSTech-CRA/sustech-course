import { Space, Typography } from 'antd';
import DOMPurify from 'dompurify';
import { useEffect, useMemo, useRef, useState } from 'react';
import type { KeyboardEvent, ReactNode } from 'react';

interface HTMLContentProps {
  html?: string | null;
  maxRows?: number;
  previewChars?: number;
  className?: string;
  /** 展开全文后显示在"收起"旁的附加操作（如跳转原文链接） */
  expandedExtra?: ReactNode;
}

function extractPlainText(html: string) {
  if (!html) return '';
  if (typeof document === 'undefined') {
    return html.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
  }
  const container = document.createElement('div');
  container.innerHTML = html;
  return (container.textContent || '').replace(/\s+/g, ' ').trim();
}

function takeText(value: string, limit: number) {
  return Array.from(value).slice(0, limit).join('');
}

// 用户富文本里的图片：补空 alt（装饰性语义，a11y 审计要求）并懒加载
// （点评图片多在首屏外，懒加载减少移动端首屏传输）。钩子对 DOMPurify
// 全局生效，afterSanitizeAttributes 阶段设置的属性不受 ALLOWED_ATTR 过滤。
DOMPurify.addHook('afterSanitizeAttributes', (node) => {
  if (node.tagName === 'IMG') {
    if (!node.hasAttribute('alt')) node.setAttribute('alt', '');
    node.setAttribute('loading', 'lazy');
    node.setAttribute('decoding', 'async');
  }
});

export function HTMLContent({ html, maxRows, previewChars, className, expandedExtra }: HTMLContentProps) {
  const contentRef = useRef<HTMLDivElement>(null);
  const [expanded, setExpanded] = useState(false);

  // 展开/收起是页面行为而非导航：role=button 让爬虫审计忽略该 <a>，
  // tabIndex + 键盘处理补齐无 href 锚点缺失的可聚焦性
  const toggleProps = (next: boolean) => ({
    role: 'button' as const,
    tabIndex: 0,
    onClick: () => setExpanded(next),
    onKeyDown: (event: KeyboardEvent) => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        setExpanded(next);
      }
    },
  });

  const normalizedHtml = useMemo(() => {
    const source = html || '';
    if (!source) return '';
    if (typeof document === 'undefined') {
      return source
        .replace(
          /<script\s+type=["']math\/tex["']\s*>([\s\S]*?)<\/script>/gi,
          (_match, equation) => `<span class="math-tex">\\(${equation}\\)</span>`,
        )
        .replace(
          /<script\s+type=["']math\/tex;\s*mode=display["']\s*>([\s\S]*?)<\/script>/gi,
          (_match, equation) => `<span class="math-tex">\\[${equation}\\]</span>`,
        );
    }
    const template = document.createElement('template');
    template.innerHTML = source;
    template.content.querySelectorAll('script[type^="math/tex"]').forEach((script) => {
      const span = document.createElement('span');
      span.className = 'math-tex';
      const equation = script.textContent || '';
      const isDisplay = script.getAttribute('type')?.includes('mode=display');
      span.textContent = isDisplay ? `\\[${equation}\\]` : `\\(${equation}\\)`;
      script.replaceWith(span);
    });
    return template.innerHTML;
  }, [html]);

  const clean = DOMPurify.sanitize(normalizedHtml, {
    ALLOWED_TAGS: [
      'a',
      'b',
      'div',
      'i',
      'em',
      'strong',
      's',
      'u',
      'p',
      'br',
      'hr',
      'ul',
      'ol',
      'li',
      'blockquote',
      'pre',
      'code',
      'span',
      'img',
      'table',
      'thead',
      'tbody',
      'tr',
      'th',
      'td',
      'figure',
      'figcaption',
      'oembed',
      'h2',
      'h3',
      'h4',
      'h5',
      'mark',
    ],
    ALLOWED_ATTR: [
      'href',
      'src',
      'alt',
      'title',
      'class',
      'target',
      'rel',
      'colspan',
      'rowspan',
      'scope',
      'url',
    ],
  });
  const plainText = useMemo(() => extractPlainText(clean), [clean]);
  const previewLimit = previewChars ?? (maxRows ? 100 : undefined);
  const isPreviewable = Boolean(previewLimit && Array.from(plainText).length > previewLimit);
  const isCollapsed = isPreviewable && !expanded;

  useEffect(() => {
    if (isCollapsed || !contentRef.current || !/[\\$]|\\\(|\\\[/.test(clean)) return;

    const ensureMathJax = () => {
      if (window.MathJax?.typesetPromise) {
        return Promise.resolve(window.MathJax);
      }
      window.MathJax = {
        tex: {
          inlineMath: [
            ['$', '$'],
            ['\\(', '\\)'],
          ],
          displayMath: [
            ['$$', '$$'],
            ['\\[', '\\]'],
          ],
        },
        svg: { fontCache: 'global' },
      };
      return new Promise<typeof window.MathJax>((resolve, reject) => {
        const existing = document.getElementById('mathjax-script') as HTMLScriptElement | null;
        if (existing) {
          existing.addEventListener('load', () => resolve(window.MathJax!));
          existing.addEventListener('error', reject);
          return;
        }
        const script = document.createElement('script');
        script.id = 'mathjax-script';
        script.async = true;
        script.src = 'https://s4.zstatic.net/ajax/libs/mathjax/3.2.2/es5/tex-svg.min.js';
        script.onload = () => resolve(window.MathJax!);
        script.onerror = reject;
        document.head.appendChild(script);
      });
    };

    ensureMathJax()
      .then((mathJax) => mathJax?.typesetPromise?.([contentRef.current]))
      .catch(() => undefined);
  }, [clean, isCollapsed]);

  if (!clean) {
    return <Typography.Text type="secondary">暂无内容</Typography.Text>;
  }

  if (isCollapsed && previewLimit) {
    return (
      <Typography.Paragraph className={className}>
        <span>{takeText(plainText, previewLimit)}...</span>
        <Typography.Link className="html-content-toggle" {...toggleProps(true)}>
          更多...
        </Typography.Link>
      </Typography.Paragraph>
    );
  }

  return (
    <>
      <Typography.Paragraph className={className}>
        <div ref={contentRef} className="html-content-body" dangerouslySetInnerHTML={{ __html: clean }} />
      </Typography.Paragraph>
      {isPreviewable && (
        <Space size={16} wrap>
          <Typography.Link className="html-content-toggle" {...toggleProps(false)}>
            收起
          </Typography.Link>
          {expandedExtra}
        </Space>
      )}
    </>
  );
}
