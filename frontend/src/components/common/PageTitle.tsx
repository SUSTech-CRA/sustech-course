import { Typography } from 'antd';
import type { ReactNode } from 'react';

interface PageTitleProps {
  title: ReactNode;
  subtitle?: ReactNode;
  extra?: ReactNode;
}

export function PageTitle({ title, subtitle, extra }: PageTitleProps) {
  return (
    <div className="page-title">
      <div>
        <Typography.Title level={1}>{title}</Typography.Title>
        {subtitle && <Typography.Text type="secondary">{subtitle}</Typography.Text>}
      </div>
      {extra && <div className="page-title-extra">{extra}</div>}
    </div>
  );
}
