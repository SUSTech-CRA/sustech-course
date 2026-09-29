import { SearchOutlined } from '@ant-design/icons';
import { Input } from 'antd';
import { useState } from 'react';
import type { FocusEvent, KeyboardEvent } from 'react';
import { useNavigate } from 'react-router-dom';

import { useSearchSuggest } from '../../hooks/useSearchSuggest';

interface NavSearchProps {
  className?: string;
  /** 跳转后的附加动作（如关闭移动端抽屉） */
  onNavigated?: () => void;
}

/**
 * 导航栏搜索框：输入即出课程/教师建议。
 * 刻意不用 AutoComplete：回车必须始终进搜索结果页，候选项只响应鼠标/直接点击
 * （AutoComplete 悬浮候选 + Enter 会选中该项，容易误触进课程页）。
 */
export function NavSearch({ className, onNavigated }: NavSearchProps) {
  const navigate = useNavigate();
  const [keyword, setKeyword] = useState('');
  const [focused, setFocused] = useState(false);
  const suggestQuery = useSearchSuggest(keyword);

  const data = suggestQuery.data;
  const open =
    focused && keyword.trim().length > 0 && !!data && data.courses.length + data.teachers.length > 0;

  const submitSearch = (value: string) => {
    const q = value.trim();
    if (!q) return;
    setFocused(false);
    navigate(`/search?q=${encodeURIComponent(q)}&type=all`);
    onNavigated?.();
  };

  const goTo = (path: string) => {
    setKeyword('');
    setFocused(false);
    navigate(path);
    onNavigated?.();
  };

  // 点击面板内部时输入框会先失焦：焦点若仍在容器内则保持面板打开
  const handleBlur = (event: FocusEvent<HTMLDivElement>) => {
    if (!event.currentTarget.contains(event.relatedTarget)) {
      setFocused(false);
    }
  };

  const handleKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'Escape') {
      setFocused(false);
    }
  };

  return (
    <div
      className={`nav-search-wrap ${className ?? ''}`}
      onFocus={() => setFocused(true)}
      onBlur={handleBlur}
    >
      <Input.Search
        allowClear
        value={keyword}
        aria-label="搜索课程、老师、点评"
        placeholder="搜索课程、老师、点评"
        enterButton={<SearchOutlined />}
        onChange={(event) => setKeyword(event.target.value)}
        onSearch={submitSearch}
        onKeyDown={handleKeyDown}
      />
      {open && (
        <div className="nav-suggest-panel">
          {data.courses.length > 0 && <div className="nav-suggest-group">课程</div>}
          {data.courses.map((course) => (
            <button
              type="button"
              key={`course-${course.id}`}
              className="nav-suggest-option"
              onClick={() => goTo(`/course/${course.id}`)}
            >
              <span className="nav-suggest-item">
                <span className="nav-suggest-name">{course.name}</span>
                {course.course_code && <span className="nav-suggest-code mono-text">{course.course_code}</span>}
                <span className="nav-suggest-meta">
                  {course.teacher_names}
                  {course.review_count > 0 ? ` · ${course.review_count} 条点评` : ''}
                </span>
              </span>
            </button>
          ))}
          {data.teachers.length > 0 && <div className="nav-suggest-group">教师</div>}
          {data.teachers.map((teacher) => (
            <button
              type="button"
              key={`teacher-${teacher.id}`}
              className="nav-suggest-option"
              onClick={() => goTo(`/teacher/${teacher.id}`)}
            >
              <span className="nav-suggest-item">
                <span className="nav-suggest-name">{teacher.name}</span>
                {teacher.title && <span className="nav-suggest-meta">{teacher.title}</span>}
              </span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
