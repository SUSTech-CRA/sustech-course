import dayjs from 'dayjs';
import relativeTime from 'dayjs/plugin/relativeTime';
import utc from 'dayjs/plugin/utc';
import 'dayjs/locale/zh-cn';

dayjs.extend(relativeTime);
dayjs.extend(utc);
dayjs.locale('zh-cn');

const TIMEZONE_PATTERN = /(Z|[+-]\d{2}:?\d{2})$/i;

export function parseApiTime(value?: string | null) {
  if (!value) return null;
  const parsed = TIMEZONE_PATTERN.test(value) ? dayjs(value) : dayjs.utc(value).local();
  return parsed.isValid() ? parsed : null;
}

export function formatDateTime(value?: string | null) {
  if (!value) return '未知时间';
  return parseApiTime(value)?.format('YYYY-MM-DD HH:mm') || '未知时间';
}

export function fromNow(value?: string | null) {
  if (!value) return '未知时间';
  return parseApiTime(value)?.fromNow() || '未知时间';
}

export function smartTime(value?: string | null) {
  if (!value) return '未知时间';
  const time = parseApiTime(value);
  if (!time) return '未知时间';
  const isOlderThanOneDay = dayjs().diff(time, 'millisecond') > 24 * 60 * 60 * 1000;
  return isOlderThanOneDay ? time.format('YYYY-MM-DD HH:mm') : time.fromNow();
}

export function termDisplay(term?: string | null) {
  if (!term || term.length !== 5) return term || '未知学期';
  const year = term.slice(0, 4);
  const season = term[4];
  if (season === '1') return `${year}秋`;
  if (season === '2') return `${Number(year) + 1}春`;
  if (season === '3') return `${Number(year) + 1}夏`;
  return '未知学期';
}

export function termListDisplay(terms?: Array<string | null | undefined>, maxCount = 2) {
  const validTerms = (terms || []).filter(Boolean) as string[];
  if (!validTerms.length) return '未知学期';
  const visible = validTerms.slice(0, maxCount).map((term) => termDisplay(term));
  return `${visible.join(' ')}${validTerms.length > maxCount ? '...' : ''}`;
}

export function currentTerm() {
  // 与老版 date_to_term 一致：9-12月为当年秋(1)，2-6月为上一年春(2)，7-8月为上一年夏(3)，1月为上一年秋(1)
  const now = dayjs();
  const month = now.month() + 1;
  if (month >= 9) return `${now.year()}1`;
  if (month >= 7) return `${now.year() - 1}3`;
  if (month >= 2) return `${now.year() - 1}2`;
  return `${now.year() - 1}1`;
}

export function numberOrDash(value?: number | string | null) {
  if (value === null || value === undefined || value === '') return '-';
  return value;
}

export function percentValue(value?: string | number | null) {
  if (value === null || value === undefined || value === '') return 0;
  const parsed = typeof value === 'number' ? value : Number.parseFloat(value);
  return Number.isFinite(parsed) ? Math.max(0, Math.min(100, parsed)) : 0;
}

export function compactTeacherNames(value?: string | null) {
  if (!value) return '教师未知';
  const maxLength = 28;
  if (value.length <= maxLength) return value;

  const names = value.split(/\s*[,，、]\s*/).filter(Boolean);
  if (names.length <= 1) return value;

  const separator = value.includes('、') ? '、' : value.includes('，') ? '，' : ', ';
  let visible = names[0];
  for (const name of names.slice(1)) {
    const candidate = `${visible}${separator}${name}`;
    if (candidate.length > maxLength) return `${visible}...`;
    visible = candidate;
  }
  return visible;
}

export function formatBytes(value?: number | null) {
  if (!value) return '-';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let size = value;
  let unitIndex = 0;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }
  const fractionDigits = unitIndex === 0 || size >= 10 ? 0 : 1;
  return `${size.toFixed(fractionDigits)} ${units[unitIndex]}`;
}

export function stripHtmlForSummary(html?: string | null, maxLength = 120) {
  if (!html) return '';
  const text = html.replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim();
  return text.length > maxLength ? `${text.slice(0, maxLength)}...` : text;
}
