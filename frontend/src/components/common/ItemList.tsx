import { Spin } from 'antd';
import type { Key, ReactNode } from 'react';

import { EmptyState } from './EmptyState';

interface ItemListProps<T> {
  dataSource: T[];
  renderItem: (item: T, index: number) => ReactNode;
  rowKey?: (item: T) => Key;
  loading?: boolean;
  emptyText?: string;
  size?: 'small' | 'medium';
  className?: string;
}

// antd v6 弃用 List 组件后的轻量替代：语义化 ul/li + Spin/Empty。
// 视觉对齐原 List：行间分割线、上下 12px（small 8px）内边距、末行无分割线；
// 行内布局为 flex + space-between，单一子元素自动占满整行（见 styles.css .item-list-*）。
export function ItemList<T>({ dataSource, renderItem, rowKey, loading, emptyText, size, className }: ItemListProps<T>) {
  if (loading) {
    return (
      <div className="item-list-loading">
        <Spin />
      </div>
    );
  }
  if (!dataSource.length) {
    return <EmptyState description={emptyText} />;
  }
  const classes = ['item-list', size === 'small' ? 'item-list-small' : null, className].filter(Boolean).join(' ');
  return (
    <ul className={classes}>
      {dataSource.map((item, index) => (
        <li key={rowKey ? rowKey(item) : index} className="item-list-item">
          {renderItem(item, index)}
        </li>
      ))}
    </ul>
  );
}

// 对齐原 List.Item.Meta 的标题 + 次要说明布局（占据行内剩余空间）。
export function ItemMeta({ title, description }: { title?: ReactNode; description?: ReactNode }) {
  return (
    <div className="item-list-meta">
      {title != null && <div className="item-list-meta-title">{title}</div>}
      {description != null && <div className="item-list-meta-description">{description}</div>}
    </div>
  );
}
